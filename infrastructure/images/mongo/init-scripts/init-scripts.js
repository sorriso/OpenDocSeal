// File: 01-init-notary.js
// Path: infrastructure/images/mongo/init-scripts/01-init-notary.js
// Version: 2
// =============================================================================
// MongoDB Initialization Script for OpenDocSeal Notary Application
// =============================================================================

// Get configuration from environment variables
const DB_NAME = process.env.NOTARY_DB_NAME || process.env.MONGO_INITDB_DATABASE || "opendocseal";
const APP_USER = process.env.NOTARY_DB_USER || "notary_user";
const APP_PASSWORD = process.env.NOTARY_DB_PASSWORD || "NotarySecurePass2025!";
const ADMIN_EMAIL = process.env.NOTARY_ADMIN_EMAIL || "admin@opendocseal.local";

// Validate required environment variables
if (!APP_PASSWORD || APP_PASSWORD === "NotarySecurePass2025!") {
    print("⚠️  WARNING: Using default password! Set NOTARY_DB_PASSWORD environment variable for production");
}

print("=== OpenDocSeal MongoDB Initialization ===");
print("Database: " + DB_NAME);
print("User: " + APP_USER);
print("Admin Email: " + ADMIN_EMAIL);

// Switch to admin database to create user
db = db.getSiblingDB('admin');

// Create application user with database-specific permissions
print("Creating notary application user...");
try {
    db.createUser({
        user: APP_USER,
        pwd: APP_PASSWORD,
        roles: [
            {
                role: "readWrite",
                db: DB_NAME
            },
            {
                role: "dbAdmin",
                db: DB_NAME
            }
        ]
    });
    print("✅ User '" + APP_USER + "' created successfully");
} catch (error) {
    if (error.code === 11000) {
        print("⚠️  User '" + APP_USER + "' already exists, skipping creation");
    } else {
        print("❌ Error creating user: " + error.message);
        throw error;
    }
}

// Switch to application database
db = db.getSiblingDB(DB_NAME);

// Create initial collections with validation schemas
print("Creating application collections...");

// Documents collection - stores document metadata
try {
    db.createCollection("documents", {
        validator: {
            $jsonSchema: {
                bsonType: "object",
                required: ["reference", "filename", "hash_sha256", "user_id", "status"],
                properties: {
                    reference: {
                        bsonType: "string",
                        description: "Document reference must be a string"
                    },
                    filename: {
                        bsonType: "string",
                        description: "Original filename"
                    },
                    hash_sha256: {
                        bsonType: "string",
                        description: "SHA256 hash of document"
                    },
                    user_id: {
                        bsonType: "string",
                        description: "User ID who uploaded document"
                    },
                    status: {
                        bsonType: "string",
                        enum: ["pending", "processing", "sealed", "failed"],
                        description: "Document processing status"
                    },
                    created_at: {
                        bsonType: "date",
                        description: "Document creation timestamp"
                    },
                    metadata: {
                        bsonType: "object",
                        description: "Custom document metadata"
                    }
                }
            }
        }
    });
} catch (error) {
    if (error.code === 48) {
        print("⚠️  Collection 'documents' already exists");
    } else {
        throw error;
    }
}

// Users collection - stores user information
try {
    db.createCollection("users", {
        validator: {
            $jsonSchema: {
                bsonType: "object",
                required: ["email", "role", "is_active"],
                properties: {
                    email: {
                        bsonType: "string",
                        pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$",
                        description: "Valid email address required"
                    },
                    role: {
                        bsonType: "string",
                        enum: ["user", "admin", "super_admin"],
                        description: "User role"
                    },
                    is_active: {
                        bsonType: "bool",
                        description: "User active status"
                    }
                }
            }
        }
    });
} catch (error) {
    if (error.code === 48) {
        print("⚠️  Collection 'users' already exists");
    } else {
        throw error;
    }
}

// Blockchain transactions collection
try {
    db.createCollection("blockchain_transactions", {
        validator: {
            $jsonSchema: {
                bsonType: "object",
                required: ["document_id", "tx_hash", "status"],
                properties: {
                    document_id: {
                        bsonType: "string",
                        description: "Reference to document"
                    },
                    tx_hash: {
                        bsonType: "string",
                        description: "Blockchain transaction hash"
                    },
                    status: {
                        bsonType: "string",
                        enum: ["pending", "confirmed", "failed"],
                        description: "Transaction status"
                    }
                }
            }
        }
    });
} catch (error) {
    if (error.code === 48) {
        print("⚠️  Collection 'blockchain_transactions' already exists");
    } else {
        throw error;
    }
}

// Create other collections (without validation for simplicity)
const simpleCollections = ["api_keys", "audit_logs"];
simpleCollections.forEach(function(collectionName) {
    try {
        db.createCollection(collectionName);
    } catch (error) {
        if (error.code === 48) {
            print("⚠️  Collection '" + collectionName + "' already exists");
        } else {
            throw error;
        }
    }
});

print("✅ Collections created successfully");

// Create indexes for performance
print("Creating database indexes...");

// Function to create index safely
function createIndexSafely(collection, indexSpec, options) {
    try {
        collection.createIndex(indexSpec, options || {});
    } catch (error) {
        if (error.code === 85) {
            print("⚠️  Index already exists: " + JSON.stringify(indexSpec));
        } else {
            throw error;
        }
    }
}

// Documents collection indexes
createIndexSafely(db.documents, { "reference": 1 }, { unique: true });
createIndexSafely(db.documents, { "hash_sha256": 1 }, { unique: true });
createIndexSafely(db.documents, { "user_id": 1 });
createIndexSafely(db.documents, { "status": 1 });
createIndexSafely(db.documents, { "created_at": 1 });
createIndexSafely(db.documents, { "user_id": 1, "created_at": -1 });

// Users collection indexes
createIndexSafely(db.users, { "email": 1 }, { unique: true });
createIndexSafely(db.users, { "role": 1 });
createIndexSafely(db.users, { "is_active": 1 });

// Blockchain transactions indexes
createIndexSafely(db.blockchain_transactions, { "document_id": 1 });
createIndexSafely(db.blockchain_transactions, { "tx_hash": 1 }, { unique: true });
createIndexSafely(db.blockchain_transactions, { "status": 1 });
createIndexSafely(db.blockchain_transactions, { "created_at": 1 });

// API keys indexes
createIndexSafely(db.api_keys, { "key_hash": 1 }, { unique: true });
createIndexSafely(db.api_keys, { "user_id": 1 });
createIndexSafely(db.api_keys, { "is_active": 1 });

// Audit logs indexes
createIndexSafely(db.audit_logs, { "user_id": 1 });
createIndexSafely(db.audit_logs, { "action": 1 });
createIndexSafely(db.audit_logs, { "timestamp": 1 });
createIndexSafely(db.audit_logs, { "timestamp": -1 });

print("✅ Indexes created successfully");

// Insert default admin user (optional and only if it doesn't exist)
print("Creating default admin user...");
try {
    const existingAdmin = db.users.findOne({ email: ADMIN_EMAIL });
    if (!existingAdmin) {
        db.users.insertOne({
            email: ADMIN_EMAIL,
            role: "super_admin",
            is_active: true,
            is_verified: true,
            created_at: new Date(),
            updated_at: new Date(),
            profile: {
                first_name: "System",
                last_name: "Administrator"
            }
        });
        print("✅ Default admin user created: " + ADMIN_EMAIL);
    } else {
        print("⚠️  Admin user already exists: " + ADMIN_EMAIL);
    }
} catch (error) {
    print("❌ Error creating admin user: " + error.message);
}

// Database statistics
print("=== Database Initialization Complete ===");
print("Database: " + DB_NAME);
print("Collections: " + db.getCollectionNames().length);
print("User: " + APP_USER);

// Display collection info
db.getCollectionNames().forEach(function(collection) {
    print("- " + collection + ": " + db.getCollection(collection).countDocuments() + " documents");
});

print("=== Initialization finished successfully ===");