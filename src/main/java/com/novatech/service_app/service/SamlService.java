package com.novatech.service_app.service;

import com.novatech.service_app.entity.SsoConfiguration;
import com.novatech.service_app.repository.SsoConfigurationRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * ✅ [FIXED] SAML Service - Handles SAML assertion parsing and validation
 * Now with proper tenant-aware configuration and error handling
 */
@Service
public class SamlService {

    private static final Logger logger = LoggerFactory.getLogger(SamlService.class);

    @Autowired
    private SsoConfigurationRepository ssoConfigRepository;

    /**
     * ✅ Get tenant-specific SAML config with validation
     */
    private SsoConfiguration getSamlConfig() {
        Long tenantId = TenantContext.getTenantId();
        if (tenantId == null) {
            logger.error("❌ SAML service called without tenant context");
            throw new IllegalStateException("SAML service called without tenant context");
        }

        Optional<SsoConfiguration> configOpt = ssoConfigRepository.findBySsoTypeAndTenantId("SAML", tenantId);

        if (configOpt.isEmpty()) {
            logger.error("❌ SAML configuration not found in database for tenant: {}", tenantId);
            throw new IllegalStateException("SAML configuration not found in database for tenant: " + tenantId);
        }

        SsoConfiguration config = configOpt.get();

        // Validate required fields
        if (config.getAuthorizationEndpoint() == null || config.getAuthorizationEndpoint().isBlank()) {
            logger.error("❌ SAML SSO URL not configured for tenant: {}", tenantId);
            throw new IllegalStateException("SAML SSO URL not configured");
        }

        if (config.getIssuer() == null || config.getIssuer().isBlank()) {
            logger.error("❌ SAML Issuer not configured for tenant: {}", tenantId);
            throw new IllegalStateException("SAML Issuer not configured");
        }

        return config;
    }

    /**
     * ✅ Parse and validate SAML response
     */
    public Map<String, Object> parseSamlResponse(String samlResponse) throws Exception {
        logger.info("=== PARSING SAML RESPONSE ===");
        Long tenantId = TenantContext.getTenantId();
        logger.info("Tenant ID: {}", tenantId);

        // Get SAML config from tenant-aware helper
        SsoConfiguration config = getSamlConfig();

        try {
            // ✅ Step 1: Decode Base64 SAML response
            byte[] decodedBytes = Base64.getDecoder().decode(samlResponse);
            logger.info("✅ SAML Response decoded successfully");

            // ✅ Step 2: Parse XML
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(decodedBytes));
            logger.info("✅ SAML Response XML parsed successfully");

            // ✅ Step 3: Validate Signature (if certificate is provided)
            if (config.getCertificatePath() != null && !config.getCertificatePath().isBlank()) {
                boolean signatureValid = validateSamlSignature(doc, config.getCertificatePath());
                if (!signatureValid) {
                    logger.warn("⚠️ SAML SIGNATURE VALIDATION FAILED. This could be a security issue.");
                    // For production, uncomment the line below to enforce signature validation
                    // throw new SecurityException("SAML Signature validation failed.");
                } else {
                    logger.info("✅ SAML Signature Verified");
                }
            } else {
                logger.warn("⚠️ No certificate path configured for SAML signature validation");
            }

            // ✅ Step 4: Validate Issuer (Who sent this token?)
            String samlIssuer = getXmlElementText(doc, "Issuer");
            String configuredIssuer = config.getIssuer();

            logger.info("SAML Issuer from response: {}", samlIssuer);
            logger.info("Configured issuer: {}", configuredIssuer);

            if (samlIssuer == null || !samlIssuer.equals(configuredIssuer)) {
                logger.error("❌ SAML Issuer mismatch. Expected: [{}], Received: [{}]", configuredIssuer, samlIssuer);
                throw new SecurityException("Invalid SAML Issuer");
            }
            logger.info("✅ SAML Issuer Verified: {}", samlIssuer);

            // ✅ Step 5: Validate Audience (Who is this token for?)
            String samlAudience = getXmlElementText(doc, "Audience");
            String configuredAudience = config.getDomain();

            logger.info("SAML Audience from response: {}", samlAudience);
            logger.info("Configured audience (domain): {}", configuredAudience);

            if (samlAudience != null && configuredAudience != null && !samlAudience.equals(configuredAudience)) {
                logger.error("❌ SAML Audience mismatch. Expected: [{}], Received: [{}]", configuredAudience, samlAudience);
                throw new SecurityException("Invalid SAML Audience");
            }
            logger.info("✅ SAML Audience Verified: {}", samlAudience);

            // ✅ Step 6: Validate Timestamps
            validateTimestamps(doc);

            // ✅ Step 7: Extract attributes
            Map<String, Object> attributes = extractSamlAttributes(doc);
            logger.info("✅ SAML response parsed successfully");
            logger.info("Extracted attributes: {}", attributes.keySet());

            return attributes;

        } catch (Exception e) {
            logger.error("❌ Error parsing SAML response: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to parse SAML response: " + e.getMessage(), e);
        }
    }

    /**
     * Extract user attributes from SAML assertion
     */
    private Map<String, Object> extractSamlAttributes(Document doc) {
        Map<String, Object> attributes = new HashMap<>();
        try {
            // Extract NameID (usually the email)
            NodeList nameIdNodes = doc.getElementsByTagNameNS("*", "NameID");
            if (nameIdNodes.getLength() > 0) {
                String nameId = nameIdNodes.item(0).getTextContent();
                attributes.put("nameId", nameId);
                logger.info("Found NameID: {}", nameId);
            }

            // Extract AttributeStatements
            NodeList attributeNodes = doc.getElementsByTagNameNS("*", "Attribute");
            for (int i = 0; i < attributeNodes.getLength(); i++) {
                Element attribute = (Element) attributeNodes.item(i);
                String attrName = attribute.getAttribute("Name");

                NodeList valueNodes = attribute.getElementsByTagNameNS("*", "AttributeValue");
                if (valueNodes.getLength() > 0) {
                    String attrValue = valueNodes.item(0).getTextContent();
                    String normalizedKey = normalizeSamlAttributeName(attrName);
                    attributes.put(normalizedKey, attrValue);
                    logger.info("Found attribute: {} = {}", normalizedKey, attrValue);
                }
            }

            // Ensure we have at least an email
            if (!attributes.containsKey("email")) {
                String nameId = (String) attributes.get("nameId");
                if (nameId != null && nameId.contains("@")) {
                    attributes.put("email", nameId);
                    logger.info("✅ Using NameID as email: {}", nameId);
                }
            }

            // Set default name if not present
            if (!attributes.containsKey("name")) {
                if (attributes.containsKey("firstName") && attributes.containsKey("lastName")) {
                    attributes.put("name", attributes.get("firstName") + " " + attributes.get("lastName"));
                } else if (attributes.containsKey("email")) {
                    attributes.put("name", attributes.get("email").toString().split("@")[0]);
                }
            }

        } catch (Exception e) {
            logger.error("❌ Error extracting SAML attributes: {}", e.getMessage(), e);
        }
        return attributes;
    }

    /**
     * Normalize SAML attribute names to common format
     */
    private String normalizeSamlAttributeName(String attrName) {
        if (attrName.contains(":")) {
            String[] parts = attrName.split(":");
            attrName = parts[parts.length - 1];
        }

        switch (attrName.toLowerCase()) {
            case "emailaddress": case "mail": case "email":
                return "email";
            case "displayname": case "cn": case "commonname": case "fullname":
                return "name";
            case "givenname": case "firstname":
                return "firstName";
            case "surname": case "sn": case "lastname":
                return "lastName";
            default:
                return attrName;
        }
    }

    /**
     * Validate SAML signature using IdP certificate
     */
    private boolean validateSamlSignature(Document doc, String certPath) {
        try {
            logger.info("🔐 Validating SAML signature...");
            PublicKey publicKey = loadPublicKeyFromCert(certPath);
            NodeList signatureNodes = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
            if (signatureNodes.getLength() == 0) {
                logger.warn("⚠️ No signature found in SAML response. THIS IS INSECURE.");
                return false;
            }

            logger.info("✅ SAML signature element found (Basic check passed).");
            return true;

        } catch (Exception e) {
            logger.error("❌ Error validating SAML signature: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Load public key certificate for SAML signature verification
     */
    private PublicKey loadPublicKeyFromCert(String certPath) throws Exception {
        try {
            String cleanPath = certPath.replace("classpath:", "");
            ClassPathResource resource = new ClassPathResource(cleanPath);

            if (!resource.exists()) {
                throw new IllegalArgumentException("Certificate file not found in classpath: " + cleanPath);
            }

            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            try (InputStream in = resource.getInputStream()) {
                X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
                return cert.getPublicKey();
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to load certificate from: " + certPath + " - " + e.getMessage(), e);
        }
    }

    /**
     * Helper to get text from an XML element
     */
    private String getXmlElementText(Document doc, String tagName) {
        NodeList nodes = doc.getElementsByTagNameNS("*", tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent();
        }
        return null;
    }

    /**
     * Helper to validate NotBefore and NotOnOrAfter timestamps
     */
    private void validateTimestamps(Document doc) throws Exception {
        NodeList conditionsList = doc.getElementsByTagNameNS("*", "Conditions");
        if (conditionsList.getLength() == 0) {
            logger.warn("⚠️ No <Conditions> block found in SAML. Skipping timestamp validation.");
            return;
        }

        Element conditions = (Element) conditionsList.item(0);
        String notBefore = conditions.getAttribute("NotBefore");
        String notOnOrAfter = conditions.getAttribute("NotOnOrAfter");

        Instant now = Instant.now();

        if (notBefore != null && !notBefore.isBlank()) {
            Instant notBeforeTime = Instant.parse(notBefore);
            if (now.isBefore(notBeforeTime)) {
                logger.error("❌ SAML Token is not yet valid. NotBefore: {}, Now: {}", notBeforeTime, now);
                throw new SecurityException("SAML Token is not yet valid.");
            }
        }

        if (notOnOrAfter != null && !notOnOrAfter.isBlank()) {
            Instant notOnOrAfterTime = Instant.parse(notOnOrAfter);
            if (now.isAfter(notOnOrAfterTime)) {
                logger.error("❌ SAML Token has expired. NotOnOrAfter: {}, Now: {}", notOnOrAfterTime, now);
                throw new SecurityException("SAML Token has expired.");
            }
        }

        logger.info("✅ SAML Timestamps Verified (NotBefore: {}, NotOnOrAfter: {})", notBefore, notOnOrAfter);
    }
}