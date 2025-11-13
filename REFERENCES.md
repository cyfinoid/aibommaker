# References

This document lists all external references, standards, and research papers that have informed the development of the AI BOM Generator and the Extended AIBOM format.

## Table of Contents

- [Academic Research](#academic-research)
- [Industry Standards & Specifications](#industry-standards--specifications)
- [Industry Best Practices](#industry-best-practices)
- [Regulatory Frameworks](#regulatory-frameworks)
- [Tool Documentation](#tool-documentation)

---

## Academic Research

### Building an Open AIBOM Standard in the Wild

**Citation:** arXiv:2510.07070v1 [cs.SE]  
**URL:** https://arxiv.org/html/2510.07070v1  
**Date:** October 2024  
**Authors:** Multiple contributors (90+ participants)

**Description:** Experience report on developing the AI Bill of Materials (AIBOM) specification. Extends ISO/IEC 5962:2021 Software Package Data Exchange (SPDX) standard to include AI-specific components like datasets and training artifacts. Development involved structured Action Research cycles with validation through EU AI Act alignment, industry use cases, practitioner interviews, and industrial case studies.

**Key Contributions:**
- Formal standardization process for AI systems
- SPDX extension for AI components
- Dataset provenance and lineage tracking
- Training artifact specifications
- EU AI Act compliance mapping
- 90+ contributor validation process

**Relevance:** Provides formal standardization direction for AIBOM. Our Extended AIBOM format is designed to be compatible with this emerging standard while providing practical, immediately useful functionality.

---

## Industry Standards & Specifications

### CycloneDX

**Version:** 1.7  
**Organization:** OWASP (Open Web Application Security Project)  
**URL:** https://cyclonedx.org/docs/1.7/  
**Specification:** https://cyclonedx.org/specification/overview/

**Description:** Lightweight SBOM standard designed for use in application security contexts and supply chain component analysis. Supports software, hardware, services, and machine learning models.

**Key Features:**
- Component type classification including `machine-learning-model`
- Properties for custom metadata
- Evidence tracking with locations
- Dependency relationships
- License information
- External references

**Relevance:** Primary format for our standard AIBOM output. Version 1.7 includes ML model support which we leverage extensively.

---

### SPDX (Software Package Data Exchange)

**Version:** 3.0.1  
**Standard:** ISO/IEC 5962:2021  
**Organization:** Linux Foundation  
**URL:** https://spdx.github.io/spdx-spec/v3.0.1/  
**Specification:** https://spdx.github.io/spdx-spec/v3.0.1/model/

**Description:** Open standard for communicating SBOM information including components, licenses, copyrights, and security references. Version 3.0 introduces AI profiles for machine learning packages.

**Key Features:**
- AI Profile for ML packages (`ai_AIPackage`)
- Software Profile for traditional packages
- License compliance tracking
- Security vulnerability references
- Relationship tracking
- JSON-LD format support

**Relevance:** Secondary format for our AIBOM output. SPDX 3.0.1 AI Profile is being extended by the open AIBOM standard (arXiv 2510.07070).

---

### ISO/IEC 5962:2021

**Title:** Information technology - Software Package Data Exchange (SPDX)  
**Organization:** ISO/IEC JTC 1/SC 7  
**Status:** Published Standard  
**Year:** 2021

**Description:** International standard for software package data exchange. Being extended for AI components through the open AIBOM standardization effort.

**Relevance:** Foundation for formal AIBOM standardization. Our tool supports SPDX 3.0.1 which implements this standard.

---

## Industry Best Practices

### Snyk: Essential Guide to AI Bills of Materials (AIBOMs)

**Organization:** Snyk  
**URL:** https://snyk.io/articles/ai-security/ai-bill-of-materials-aibom/  
**Type:** Industry Guide

**Description:** Comprehensive guide on AI Bills of Materials covering purpose, benefits, components, and implementation strategies. Provides 8 actionable tips for AIBOM creation and discusses the AIBOM spectrum.

**8 Actionable Tips Implemented:**
1. ✅ Start with a basic inventory (dependencies, models, frameworks, hardware)
2. ✅ Identify risks and limitations (risk assessment detector)
3. ✅ Maintain a history of model lineage (version tracking where detectable)
4. ✅ Review existing frameworks (CycloneDX, SPDX support)
5. ✅ Automate collection as part of pipelines (GitHub API integration)
6. ✅ Adopt selectively (high-risk model flagging)
7. ✅ Align with regulations (EU AI Act, NIST compliance indicators)
8. ✅ Enhance reproducibility (all components documented with versions)

**Key Concepts:**
- AIBOM Spectrum (expansiveness vs simplicity)
- Privacy vs transparency balance
- Model provenance and accountability
- Regulatory compliance

**Relevance:** Core influence on our Extended AIBOM format design. Guided our approach to comprehensive AI system documentation.

---

### Trail of Bits: Response to US Army RFI on Developing AIBOM Tools

**Organization:** Trail of Bits  
**URL:** https://blog.trailofbits.com/2024/02/28/our-response-to-the-us-armys-rfi-on-developing-aibom-tools/  
**Date:** February 28, 2024  
**Type:** Technical RFI Response

**Description:** Detailed response to US Army Request for Information on AIBOM tool development. Outlines AIBOM structure, limitations, and complementary security techniques needed for AI system security.

**Proposed AIBOM Structure:**
1. SBOM for build/validation components
2. Model properties (architecture, training data, hyperparameters)
3. Data lineage and pedigree

**Key Recommendations Implemented:**
- ✅ Hardware Bill of Materials (HBOM) for GPU/TPU
- ✅ Infrastructure tracking (deployment platforms)
- ✅ ML framework detection
- ✅ Model type classification
- ⚠️ Data transformation tracking (library detection only)
- ⚠️ Training environment (partially - from configs)

**Identified Limitations:**
- Dynamic training aspects (training data order)
- Runtime behaviors
- Custom code vulnerabilities
- Privacy vs processing trade-offs

**Complementary Techniques:**
- Anomaly detection
- Data signing and integrity checks
- Model signing
- Environment verification

**Relevance:** Informed our hardware detection, infrastructure tracking, and risk assessment features. Highlighted what can and cannot be detected from code alone.

---

## Regulatory Frameworks

### NIST AI Risk Management Framework (AI RMF)

**Version:** 1.0  
**Organization:** National Institute of Standards and Technology (NIST)  
**URL:** https://www.nist.gov/itl/ai-risk-management-framework  
**Publication:** https://doi.org/10.6028/NIST.AI.100-1  
**Date:** January 2023

**Description:** Framework for better managing risks to individuals, organizations, and society associated with artificial intelligence. Voluntary, rights-preserving, non-sector-specific approach.

**Key Components:**
- Govern: Culture of risk management
- Map: Context and associated risks
- Measure: Assess, analyze, track AI risks
- Manage: Regular monitoring and response

**Relevance:** Our risk assessment detector aligns with NIST AI RMF principles by identifying and documenting AI system risks, limitations, and governance considerations.

---

### EU Artificial Intelligence Act

**Regulation:** Regulation (EU) 2024/1689  
**Status:** Adopted June 2024, entered into force August 2024  
**URL:** https://artificialintelligenceact.eu/  
**Official Text:** https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689

**Description:** First comprehensive legal framework on AI globally. Risk-based approach with different requirements based on AI system risk levels.

**Risk Categories:**
- Unacceptable risk (prohibited)
- High risk (strict requirements)
- Limited risk (transparency obligations)
- Minimal risk (no obligations)

**Key Requirements:**
- Technical documentation
- Risk management systems
- Data governance
- Transparency and provision of information
- Human oversight
- Accuracy, robustness, cybersecurity

**Relevance:** Our governance detector identifies documentation that supports EU AI Act compliance, including:
- Intended use documentation
- Limitations and constraints
- Bias and fairness considerations
- Risk assessments
- Transparency requirements

---

### US Executive Order 14110 on AI

**Title:** Executive Order on the Safe, Secure, and Trustworthy Development and Use of Artificial Intelligence  
**Issued:** October 30, 2023  
**URL:** https://www.whitehouse.gov/briefing-room/presidential-actions/2023/10/30/executive-order-on-the-safe-secure-and-trustworthy-development-and-use-of-artificial-intelligence/

**Description:** Establishes new standards for AI safety and security, protects privacy, advances equity and civil rights, stands up for consumers and workers, promotes innovation and competition, advances American leadership globally, and ensures responsible government use.

**Key Provisions:**
- AI safety and security standards
- Reporting requirements for large AI models
- Standards for detecting AI-generated content
- Protection against AI-enabled fraud
- Civil rights protections
- Privacy safeguards

**Relevance:** Informs our documentation completeness checks and risk assessment criteria for AI systems.

---

## Tool Documentation

### GitHub API

**Version:** REST API v3, GraphQL API v4  
**Documentation:** https://docs.github.com/en/rest  
**Rate Limits:** https://docs.github.com/en/rest/rate-limit

**Features Used:**
- Repository metadata
- File tree retrieval
- File content access
- Dependency Graph SBOM API
- Search API for code patterns
- Rate limit handling

**Relevance:** Core API for repository analysis and SBOM generation.

---

### HuggingFace Hub API

**Documentation:** https://huggingface.co/docs/hub/api  
**Model API:** https://huggingface.co/api/models

**Features Used:**
- Model metadata retrieval
- Model card information
- License information
- Download statistics
- Task/pipeline classification

**Relevance:** Enhanced model information for HuggingFace models detected in repositories.

---

## Additional Resources

### CycloneDX Tool Center

**URL:** https://cyclonedx.org/tool-center/  
**Description:** Registry of tools that support CycloneDX SBOM format

**Status:** AI BOM Generator listed as a CycloneDX-compatible tool

---

### OWASP Dependency-Track

**URL:** https://dependencytrack.org/  
**Description:** Intelligent Component Analysis platform for managing software supply chain risk

**Relevance:** Compatible with our CycloneDX output for supply chain analysis.

---

## Research Areas & Future Work

### Areas Requiring Further Standardization

Based on industry research and the open AIBOM standard:

1. **Dataset Provenance**
   - Formal specifications in development (arXiv 2510.07070)
   - Not yet detectable from code repositories

2. **Training Artifacts**
   - Hyperparameter tracking
   - Training configuration standards
   - Partially detectable from config files

3. **Model Performance Metrics**
   - Accuracy, bias, fairness measurements
   - Requires runtime data or documentation parsing
   - Standards in development

4. **AI/ML Vulnerability Database**
   - Similar to CVE for traditional software
   - Industry effort needed
   - Would enable automated vulnerability detection

5. **Carbon Footprint Tracking**
   - Training and inference emissions
   - Requires hardware specs and runtime data
   - Emerging research area

---

## Citation Format

When citing this tool or format:

```
AI BOM Generator (2025). Extended AI Bill of Materials Format v1.0.0.
Cyfinoid Research. https://github.com/cyfinoid/aibommaker
```

For the Extended AIBOM specification:

```
Extended AIBOM Specification v1.0.0 (2025). Based on industry best practices
from Snyk, Trail of Bits, and alignment with emerging AIBOM standards (arXiv
2510.07070). https://github.com/cyfinoid/aibommaker/blob/main/docs/EXTENDED_AIBOM_SPEC.md
```

---

## Maintaining This Document

This references document should be updated when:
- New standards are adopted or updated
- Additional research papers inform development
- Regulatory frameworks are modified
- New industry best practices emerge

**Last Updated:** November 2025  
**Maintainer:** Cyfinoid Research

---

## Acknowledgments

We acknowledge the work of:
- The 90+ contributors to the open AIBOM standard (arXiv 2510.07070)
- OWASP CycloneDX community
- Linux Foundation SPDX workgroup
- Snyk security research team
- Trail of Bits security research team
- NIST AI Risk Management Framework contributors
- EU AI Act working groups
- GitHub and HuggingFace for API access

---

**Note:** All references are cited for informational and educational purposes. This tool implements best practices from these sources to provide practical, immediately useful AIBOM generation while formal standards continue to develop.

