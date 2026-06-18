package com.llmshark.mobile

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView

/**
 * Adapter for chat messages
 */
class MessageAdapter : RecyclerView.Adapter<MessageAdapter.MessageViewHolder>() {
    
    private val messages = mutableListOf<DisplayMessage>()
    
    /**
     * Add a message to the list
     */
    fun addMessage(message: DisplayMessage) {
        messages.add(message)
        notifyItemInserted(messages.size - 1)
    }
    
    /**
     * Update the last message content (for streaming)
     */
    fun updateLastMessage(content: String) {
        if (messages.isNotEmpty()) {
            val lastMessage = messages.last()
            messages[messages.size - 1] = lastMessage.copy(content = content)
            notifyItemChanged(messages.size - 1)
        }
    }
    
    /**
     * Update a specific message by index (for streaming)
     */
    fun updateMessage(index: Int, message: DisplayMessage) {
        if (index in 0 until messages.size) {
            messages[index] = message
            notifyItemChanged(index)
        }
    }
    
    /**
     * Remove a specific message by index
     */
    fun removeMessage(index: Int) {
        if (index in 0 until messages.size) {
            messages.removeAt(index)
            notifyItemRemoved(index)
        }
    }
    
    /**
     * Clear all messages
     */
    fun clearMessages() {
        val size = messages.size
        messages.clear()
        notifyItemRangeRemoved(0, size)
    }
    
    /**
     * Get all messages
     */
    fun getMessages(): List<DisplayMessage> = messages.toList()
    
    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): MessageViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_message, parent, false)
        return MessageViewHolder(view)
    }
    
    override fun onBindViewHolder(holder: MessageViewHolder, position: Int) {
        holder.bind(messages[position])
    }
    
    override fun getItemCount(): Int = messages.size
    
    class MessageViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val roleText: TextView = itemView.findViewById(R.id.roleText)
        private val contentText: TextView = itemView.findViewById(R.id.contentText)
        private val thinkingSection: View = itemView.findViewById(R.id.thinkingSection)
        private val thinkingToggle: TextView = itemView.findViewById(R.id.thinkingToggle)
        private val thinkingContent: TextView = itemView.findViewById(R.id.thinkingContent)
        
        private var thinkingExpanded = false
        
        fun bind(message: DisplayMessage) {
            // Set role
            roleText.text = when (message.role) {
                "user" -> "👤 用户"
                "assistant" -> "🤖 LLM-Shark Agent"
                "system" -> "⚙️ 系统"
                else -> message.role
            }
            
            // Set content
            contentText.text = message.content
            
            // Handle thinking section
            if (!message.thinkingContent.isNullOrEmpty()) {
                thinkingSection.visibility = View.VISIBLE
                thinkingContent.text = message.thinkingContent
                thinkingExpanded = message.thinkingExpanded
                
                thinkingContent.visibility = if (thinkingExpanded) View.VISIBLE else View.GONE
                thinkingToggle.text = if (thinkingExpanded) I18nHelper.chat("thinkingProcess").replace("▼", "▲") else I18nHelper.chat("thinkingProcess")
                
                thinkingToggle.setOnClickListener {
                    thinkingExpanded = !thinkingExpanded
                    thinkingContent.visibility = if (thinkingExpanded) View.VISIBLE else View.GONE
                    thinkingToggle.text = if (thinkingExpanded) I18nHelper.chat("thinkingProcess").replace("▼", "▲") else I18nHelper.chat("thinkingProcess")
                }
            } else {
                thinkingSection.visibility = View.GONE
            }
        }
    }
}

/**
 * Display message with parsed sections
 */
data class DisplayMessage(
    val role: String,
    val content: String,
    val thinkingContent: String? = null,
    val thinkingExpanded: Boolean = false
) {
    companion object {
        /**
         * Create a display message from raw LLM response
         */
        fun fromLlmResponse(role: String, rawContent: String): DisplayMessage {
            val parsed = MessageParser.parse(rawContent)
            
            if (!parsed.hasSections()) {
                // No structured sections, return raw content
                return DisplayMessage(
                    role = role,
                    content = rawContent.trim()
                )
            }
            
            // Get main content (excluding thinking)
            val mainContent = parsed.sections
                .filter { it.key != "thinking" }
                .joinToString("\n\n") { section ->
                    buildString {
                        append("### ${section.title}\n")
                        append(section.content.trim())
                    }
                }
            
            // Get thinking content
            val thinkingContent = parsed.getThinkingSection()?.content?.trim()
            
            // Thinking should be expanded if formal hasn't started yet
            val thinkingExpanded = !parsed.formalStarted && thinkingContent != null
            
            return DisplayMessage(
                role = role,
                content = mainContent.ifEmpty { rawContent.trim() },
                thinkingContent = thinkingContent,
                thinkingExpanded = thinkingExpanded
            )
        }
    }
}
