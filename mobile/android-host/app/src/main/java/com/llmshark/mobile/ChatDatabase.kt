package com.llmshark.mobile

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

/**
 * Conversation record
 */
data class Conversation(
    val id: Long = 0,
    val createdAt: Long = 0,
    val queryJson: String = "",
    val caseIds: List<String> = emptyList(),
    val title: String? = null,
    val roundCount: Int = 0
)

/**
 * Message record
 */
data class Message(
    val id: Long = 0,
    val conversationId: Long = 0,
    val role: String = "",
    val content: String = "",
    val createdAt: Long = 0
)

/**
 * SQLite database for chat history
 */
class ChatDatabase(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {
    
    companion object {
        private const val DATABASE_NAME = "llmshark_chat.db"
        private const val DATABASE_VERSION = 1
        
        const val TABLE_CONVERSATIONS = "conversations"
        const val TABLE_MESSAGES = "messages"
        
        private const val CREATE_CONVERSATIONS_TABLE = """
            CREATE TABLE conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at INTEGER NOT NULL,
                query_json TEXT NOT NULL,
                case_ids TEXT,
                title TEXT,
                round_count INTEGER DEFAULT 0
            )
        """
        
        private const val CREATE_MESSAGES_TABLE = """
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
            )
        """
        
        private const val CREATE_INDEX_MESSAGES_CONVERSATION = 
            "CREATE INDEX idx_messages_conversation ON messages(conversation_id)"
        private const val CREATE_INDEX_CONVERSATIONS_CREATED = 
            "CREATE INDEX idx_conversations_created ON conversations(created_at DESC)"
    }
    
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(CREATE_CONVERSATIONS_TABLE)
        db.execSQL(CREATE_MESSAGES_TABLE)
        db.execSQL(CREATE_INDEX_MESSAGES_CONVERSATION)
        db.execSQL(CREATE_INDEX_CONVERSATIONS_CREATED)
    }
    
    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS messages")
        db.execSQL("DROP TABLE IF EXISTS conversations")
        onCreate(db)
    }
}

/**
 * Repository for chat history operations
 */
class ChatRepository(context: Context) {
    private val dbHelper = ChatDatabase(context)
    
    /**
     * Create a new conversation
     */
    fun createConversation(queryJson: String, caseIds: List<String>): Long {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("created_at", System.currentTimeMillis())
            put("query_json", queryJson)
            put("case_ids", caseIds.joinToString(","))
            put("round_count", 0)
        }
        return db.insert(ChatDatabase.TABLE_CONVERSATIONS, null, values)
    }
    
    /**
     * Add a message to a conversation
     */
    fun addMessage(conversationId: Long, role: String, content: String): Long {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("conversation_id", conversationId)
            put("role", role)
            put("content", content)
            put("created_at", System.currentTimeMillis())
        }
        val id = db.insert(ChatDatabase.TABLE_MESSAGES, null, values)
        
        // Update round count when user sends a message
        if (role == "user") {
            db.execSQL(
                "UPDATE conversations SET round_count = round_count + 1 WHERE id = ?",
                arrayOf(conversationId)
            )
        }
        
        return id
    }
    
    /**
     * Get a conversation by ID
     */
    fun getConversation(conversationId: Long): Conversation? {
        val db = dbHelper.readableDatabase
        val cursor = db.query(
            ChatDatabase.TABLE_CONVERSATIONS,
            null,
            "id = ?",
            arrayOf(conversationId.toString()),
            null, null, null
        )
        
        cursor.use {
            if (it.moveToFirst()) {
                return Conversation(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    createdAt = it.getLong(it.getColumnIndexOrThrow("created_at")),
                    queryJson = it.getString(it.getColumnIndexOrThrow("query_json")),
                    caseIds = it.getString(it.getColumnIndexOrThrow("case_ids"))
                        ?.split(",")
                        ?.filter { s -> s.isNotBlank() } ?: emptyList(),
                    title = it.getString(it.getColumnIndexOrThrow("title")),
                    roundCount = it.getInt(it.getColumnIndexOrThrow("round_count"))
                )
            }
        }
        return null
    }
    
    /**
     * Get messages for a conversation
     */
    fun getMessages(conversationId: Long, limit: Int = 50, offset: Int = 0): List<Message> {
        val db = dbHelper.readableDatabase
        val messages = mutableListOf<Message>()
        
        val cursor = db.query(
            ChatDatabase.TABLE_MESSAGES,
            null,
            "conversation_id = ?",
            arrayOf(conversationId.toString()),
            null, null,
            "created_at ASC",
            "$offset, $limit"
        )
        
        cursor.use {
            while (it.moveToNext()) {
                messages.add(Message(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    conversationId = it.getLong(it.getColumnIndexOrThrow("conversation_id")),
                    role = it.getString(it.getColumnIndexOrThrow("role")),
                    content = it.getString(it.getColumnIndexOrThrow("content")),
                    createdAt = it.getLong(it.getColumnIndexOrThrow("created_at"))
                ))
            }
        }
        
        return messages
    }
    
    /**
     * Delete a conversation and its messages
     */
    fun deleteConversation(conversationId: Long) {
        val db = dbHelper.writableDatabase
        db.delete(ChatDatabase.TABLE_CONVERSATIONS, "id = ?", arrayOf(conversationId.toString()))
    }
    
    /**
     * Get all conversations (most recent first)
     */
    fun getAllConversations(limit: Int = 20): List<Conversation> {
        val db = dbHelper.readableDatabase
        val conversations = mutableListOf<Conversation>()
        
        val cursor = db.query(
            ChatDatabase.TABLE_CONVERSATIONS,
            null,
            null, null, null, null,
            "created_at DESC",
            limit.toString()
        )
        
        cursor.use {
            while (it.moveToNext()) {
                conversations.add(Conversation(
                    id = it.getLong(it.getColumnIndexOrThrow("id")),
                    createdAt = it.getLong(it.getColumnIndexOrThrow("created_at")),
                    queryJson = it.getString(it.getColumnIndexOrThrow("query_json")),
                    caseIds = it.getString(it.getColumnIndexOrThrow("case_ids"))
                        ?.split(",")
                        ?.filter { s -> s.isNotBlank() } ?: emptyList(),
                    title = it.getString(it.getColumnIndexOrThrow("title")),
                    roundCount = it.getInt(it.getColumnIndexOrThrow("round_count"))
                ))
            }
        }
        
        return conversations
    }
    
    /**
     * Update conversation title
     */
    fun updateTitle(conversationId: Long, title: String) {
        val db = dbHelper.writableDatabase
        val values = ContentValues().apply {
            put("title", title)
        }
        db.update(ChatDatabase.TABLE_CONVERSATIONS, values, "id = ?", arrayOf(conversationId.toString()))
    }
    
    /**
     * Clear all conversations
     */
    fun clearAll() {
        val db = dbHelper.writableDatabase
        db.delete(ChatDatabase.TABLE_CONVERSATIONS, null, null)
    }
}
