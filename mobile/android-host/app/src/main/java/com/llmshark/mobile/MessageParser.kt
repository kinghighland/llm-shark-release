package com.llmshark.mobile

/**
 * Represents a section in the LLM response
 */
data class MessageSection(
    val key: String,        // thinking, diagnosis, failure, reference
    val title: String,      // Display title
    val content: String     // Section content (cleaned, no tags)
)

/**
 * Parsed LLM message with sections
 */
data class ParsedMessage(
    val sections: List<MessageSection>,
    val rawContent: String,
    val formalStarted: Boolean
) {
    fun getSection(key: String): MessageSection? = sections.find { it.key == key }
    fun getThinkingSection(): MessageSection? = getSection("thinking")
    fun hasSections(): Boolean = sections.isNotEmpty()
}

/**
 * Parser for LLM response messages
 * 
 * Handles section markers in format: <section:key|Title>
 * Also handles closing tags: </section:key>
 */
object MessageParser {
    
    // Section key aliases
    private val SECTION_KEY_ALIASES = mapOf(
        "thinking" to "thinking",
        "thought" to "thinking",
        "diagnosis" to "diagnosis",
        "conclusion" to "diagnosis",
        "failure" to "failure",
        "process" to "failure",
        "reference" to "reference",
        "cases" to "reference",
        "sequence" to "sequence",
        "diagram" to "sequence",
        "signaling" to "signaling",
        "table" to "signaling",
        "formal" to "formal"
    )
    
    // Default titles
    private val SECTION_DEFAULT_TITLES = mapOf(
        "thinking" to "Thinking Process",
        "diagnosis" to "诊断结论",
        "failure" to "故障过程",
        "reference" to "参考案例",
        "sequence" to "时序图",
        "signaling" to "信令表"
    )
    
    // Pattern for opening tag: <section:key|title> or <section:key>
    private val OPEN_TAG_PATTERN = Regex(
        """<\s*section\s*:\s*([a-zA-Z_]+)\s*(?:\|\s*([^>]*))?\s*>"""
    )
    
    // Pattern for closing tag: </section:key>
    private val CLOSE_TAG_PATTERN = Regex(
        """</\s*section\s*:\s*([a-zA-Z_]+)\s*>"""
    )
    
    // Pattern for any section tag (open or close) for removal
    private val ANY_SECTION_TAG_PATTERN = Regex(
        """</?\s*section\s*:[^>]*>"""
    )
    
    /**
     * Parse LLM response into sections
     */
    fun parse(content: String): ParsedMessage {
        val lines = content.lines()
        val sections = mutableListOf<MessageSection>()
        var currentKey: String? = null
        var currentTitle: String = ""
        val currentContent = StringBuilder()
        var formalStarted = false
        var foundAnySection = false
        
        for (line in lines) {
            val trimmedLine = line.trim()
            
            // Check for opening tag
            val openMatch = OPEN_TAG_PATTERN.find(trimmedLine)
            if (openMatch != null && (trimmedLine == openMatch.value || trimmedLine.startsWith(openMatch.value))) {
                // Save previous section if exists
                if (currentKey != null && currentContent.isNotEmpty()) {
                    val cleanedContent = cleanContent(currentContent.toString())
                    if (cleanedContent.isNotBlank()) {
                        sections.add(MessageSection(currentKey, currentTitle, cleanedContent))
                    }
                    currentContent.clear()
                }
                
                val rawKey = openMatch.groupValues[1].lowercase()
                val key = SECTION_KEY_ALIASES[rawKey] ?: rawKey
                val title = openMatch.groupValues[2].trim().ifEmpty { null }
                    ?: SECTION_DEFAULT_TITLES[key] ?: ""
                
                foundAnySection = true
                
                if (key == "formal") {
                    formalStarted = true
                    currentKey = null
                } else {
                    currentKey = key
                    currentTitle = title
                }
                continue
            }
            
            // Check for closing tag
            val closeMatch = CLOSE_TAG_PATTERN.find(trimmedLine)
            if (closeMatch != null && (trimmedLine == closeMatch.value || trimmedLine.startsWith(closeMatch.value))) {
                // Save current section
                if (currentKey != null && currentContent.isNotEmpty()) {
                    val cleanedContent = cleanContent(currentContent.toString())
                    if (cleanedContent.isNotBlank()) {
                        sections.add(MessageSection(currentKey, currentTitle, cleanedContent))
                    }
                    currentContent.clear()
                }
                currentKey = null
                continue
            }
            
            // Add content to current section
            if (currentKey != null) {
                if (currentContent.isNotEmpty()) {
                    currentContent.append("\n")
                }
                currentContent.append(line)
            }
        }
        
        // Save last section if exists
        if (currentKey != null && currentContent.isNotEmpty()) {
            val cleanedContent = cleanContent(currentContent.toString())
            if (cleanedContent.isNotBlank()) {
                sections.add(MessageSection(currentKey, currentTitle, cleanedContent))
            }
        }
        
        // If no sections found, return empty
        if (!foundAnySection || sections.isEmpty()) {
            return ParsedMessage(emptyList(), content, false)
        }
        
        return ParsedMessage(sections, content, formalStarted)
    }
    
    /**
     * Clean content by removing any remaining section tags
     */
    private fun cleanContent(content: String): String {
        return ANY_SECTION_TAG_PATTERN.replace(content, "").trim()
    }
    
    /**
     * Remove all section tags from content (for display)
     */
    fun stripAllTags(content: String): String {
        return ANY_SECTION_TAG_PATTERN.replace(content, "")
    }
    
    /**
     * Extract thinking content
     */
    fun extractThinking(content: String): String? {
        return parse(content).getThinkingSection()?.content
    }
    
    /**
     * Extract main content (excluding thinking)
     */
    fun extractMainContent(content: String): String {
        val parsed = parse(content)
        return parsed.sections
            .filter { it.key != "thinking" }
            .joinToString("\n\n") { 
                buildString {
                    append("### ${it.title}\n")
                    append(it.content.trim())
                }
            }
    }
    
    /**
     * Check if content has structured sections
     */
    fun hasStructuredSections(content: String): Boolean {
        return parse(content).hasSections()
    }
}
