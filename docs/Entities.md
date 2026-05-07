# Entities

This document defines the core entity categories used in `cryptic-cti` for multilingual cyber threat lead normalization and triage.

---

## 1. `malware_family`
`
**Definition**  
Canonical malware or tooling family names referenced in lead text.

**Common normalizations**  
- Normalize capitalization to a canonical family name.  
- Collapse spacing variants into the same family name.  
- Collapse obvious shorthand or alternate naming into the canonical family name.  
- Map Chinese-language references or translated mentions to the canonical English family name where appropriate.  

**Example normalized outputs**  
- `RedLine`  
- `Lumma`  
- `Raccoon Stealer`

---

## 2. `actor_handle`

**Definition**  
Usernames, seller handles, aliases, forum identities, channel names, or repeated poster identifiers referenced in lead text. 

**Common normalizations**  
- Normalize to lowercase.  
- Collapse minor punctuation and spacing variants into one canonical handle.  
- Collapse obvious alias variants where context strongly suggests they refer to the same handle.  
- Preserve the original raw handle separately if needed for traceability.  

**Example normalized outputs**  
- `shadowmarket_01`  
- `credmaster88`  
- `redlogseller`

---

## 3. `activity_term`

**Definition**  
Terms describing the observed or advertised activity in the lead text.

**Common normalizations**  
- Normalize semantically similar phrases into a small set of analytic labels.  
- Collapse singular/plural phrasing into one normalized activity type.  
- Map common Chinese-language activity phrases to the corresponding normalized English label.  
- Use lowercase underscored labels for normalized output.  

**Example normalized outputs**  
- `stealer_log_sale`  
- `credential_sale`  
- `credential_dataset`  
- `access_broker_offer`  
- `data_dump`

---

## 4. `contact_method`

**Definition**  
Communication or contact channels referenced in lead text for follow-up, coordination, sale, or negotiation.

**Common normalizations**  
- Normalize shorthand platform references to canonical platform names.  
- Collapse common slang or abbreviations into one contact method label.  
- Map Chinese-language platform references to canonical English names where appropriate.  
- Use lowercase underscored labels for generic contact types.  

**Example normalized outputs**  
- `Telegram`  
- `TOX`  
- `Jabber`  
- `private_message`  
- `email_contact`

---

## 5. `infrastructure_indicator`

**Definition**  
Operationally relevant infrastructure or technical identifiers referenced in lead text.

**Common normalizations**  
- Normalize domains to lowercase.  
- Preserve exact technical values for indicators unless formatting cleanup is needed.  
- Strip obvious surrounding punctuation from extracted indicators.  
- Normalize indicator subtype separately where needed.  

**Example normalized outputs**  
- `example-market[.]com`  
- `abc123xyz456.onion`  
- `185.220.101.4`  
- `seller@protonmail.com`  
- `bc1qexamplewalletstring`

---

## 6. `target_sector`

**Definition**  
Industry or victim-sector references appearing in lead text.

**Common normalizations**  
- Collapse near-synonyms into one canonical sector label.  
- Map Chinese-language sector references to the corresponding normalized English label.  
- Use lowercase underscored labels for normalized output.  

**Example normalized outputs**  
- `finance_sector`  
- `healthcare_sector`  
- `retail_sector`  
- `government_sector`  
- `education_sector`

---

## 7. `geography_region`

**Definition**  
Country, region, city, or geographic references relevant to the lead text.

**Common normalizations**  
- Normalize place names to one canonical English form.  
- Collapse regional abbreviations into consistent normalized labels.  
- Map Chinese-language geographic references to the corresponding normalized English label where appropriate.  
- Use lowercase underscored labels for region-group outputs where helpful.  

**Example normalized outputs**  
- `United States`  
- `Hong Kong`  
- `China`  
- `APAC`  
- `Europe`

---

## 8. `language_script`

**Definition**  
Language or script metadata associated with the lead text or extracted content.

**Common normalizations**  
- Normalize language labels into a fixed controlled vocabulary.  
- Distinguish between Simplified Chinese and Traditional Chinese when possible.  
- Use a mixed-language label where multiple languages/scripts appear in the same lead.  
- Treat transliterated cyber slang as a note or sub-label when relevant.  

**Example normalized outputs**  
- `English`  
- `Simplified_Chinese`  
- `Traditional_Chinese`  
- `mixed_language`

---

## 9. `source_type`

**Definition**  
The type of source or lead container from which the text originated.

**Common normalizations**  
- Normalize source descriptions into a fixed set of controlled source-type labels.  
- Collapse close variants into one source-type category.  
- Use lowercase underscored labels for normalized output.  

**Example normalized outputs**  
- `forum_post`  
- `marketplace_listing`  
- `chat_message`  
- `alert_digest`  
- `public_report_excerpt`  
- `channel_post`

---