package quickstart;

import com.mongodb.AutoEncryptionSettings;
import com.mongodb.ClientEncryptionSettings;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;
import com.mongodb.client.model.CreateCollectionOptions;
import com.mongodb.client.model.Projections;
import com.mongodb.client.model.vault.EncryptOptions;
import com.mongodb.client.model.vault.StringOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonInt32;
import org.bson.BsonBoolean;
import org.bson.BsonString;
import org.bson.Document;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Minimal getting-started example of explicit (manual) Queryable Encryption.
// Mirrors driver-quickstarts/explicitencrypt.py using the MongoDB Java sync driver.
public class ExplicitEncrypt {

    public static void main(final String[] args) {
        // A local master key is 96 random bytes. In production use a KMS.
        byte[] localMasterKey = new byte[96];
        new SecureRandom().nextBytes(localMasterKey);

        Map<String, Map<String, Object>> kmsProviders = new HashMap<>();
        Map<String, Object> local = new HashMap<>();
        local.put("key", localMasterKey);
        kmsProviders.put("local", local);

        String keyVaultNamespace = "keyvault.datakeys";

        // The MongoClient used to read/write to the key vault.
        // This can be the same MongoClient used by the main application.
        try (MongoClient keyVaultClient = MongoClients.create()) {
            keyVaultClient.getDatabase("keyvault").getCollection("datakeys").drop();

            ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder()
                    .keyVaultMongoClientSettings(MongoClientSettings.builder()
                            .applyConnectionString(new com.mongodb.ConnectionString("mongodb://localhost:27017"))
                            .build())
                    .keyVaultNamespace(keyVaultNamespace)
                    .kmsProviders(kmsProviders)
                    .build();

            try (ClientEncryption clientEncryption = ClientEncryptions.create(clientEncryptionSettings)) {
                // Create a new data key for the encrypted field.
                BsonBinary keyId = clientEncryption.createDataKey("local");

                // Describe the encrypted field for the collection.
                BsonDocument field = new BsonDocument()
                        .append("keyId", keyId)
                        .append("path", new org.bson.BsonString("secret"))
                        .append("bsonType", new org.bson.BsonString("string"))
                        .append("queries", new BsonDocument()
                                .append("queryType", new org.bson.BsonString("prefixPreview"))
                                .append("strMinQueryLength", new BsonInt32(2))
                                .append("strMaxQueryLength", new BsonInt32(10))
                                .append("caseSensitive", new BsonBoolean(true))
                                .append("diacriticSensitive", new BsonBoolean(true))
                                .append("contention", new BsonInt32(0)));
                List<BsonDocument> fields = new ArrayList<>();
                fields.add(field);
                BsonDocument encryptedFields = new BsonDocument("fields", new org.bson.BsonArray(fields));

                // AutoEncryptionSettings with bypassQueryAnalysis=true: the driver
                // manages the QE metadata collections but does NOT auto-encrypt.
                // We supply already-encrypted payloads ourselves (explicit encryption).
                AutoEncryptionSettings autoEncryptionSettings = AutoEncryptionSettings.builder()
                        .keyVaultNamespace(keyVaultNamespace)
                        .kmsProviders(kmsProviders)
                        .bypassQueryAnalysis(true)
                        .build();

                MongoClientSettings encryptedClientSettings = MongoClientSettings.builder()
                        .applyConnectionString(new com.mongodb.ConnectionString("mongodb://localhost:27017"))
                        .autoEncryptionSettings(autoEncryptionSettings)
                        .build();

                try (MongoClient encryptedClient = MongoClients.create(encryptedClientSettings)) {
                    encryptedClient.getDatabase("test").drop();
                    MongoDatabase db = encryptedClient.getDatabase("test");

                    // Create the collection with encrypted fields.
                    db.createCollection("coll", new CreateCollectionOptions()
                            .encryptedFields(encryptedFields));
                    MongoCollection<Document> coll = db.getCollection("coll");

                    // Create an encrypted payload explicitly.
                    BsonBinary insertPayload = clientEncryption.encrypt(new BsonString("foobar"), new EncryptOptions("String")
                            .keyId(keyId)
                            .stringOptions(new StringOptions().prefixOptions(
                                    new BsonDocument()
                                            .append("strMinQueryLength", new BsonInt32(2))
                                            .append("strMaxQueryLength", new BsonInt32(10))
                            ).caseSensitive(true).diacriticSensitive(true))
                            .contentionFactor(0L));

                    // Insert encrypted "foobar".
                    coll.insertOne(new Document("secret", insertPayload));

                    // Query with prefix "foo":
                    BsonBinary queryPayload = clientEncryption.encrypt(new BsonString("foo"), new EncryptOptions("String")
                            .queryType("prefixPreview")
                            .keyId(keyId)
                            .stringOptions(new StringOptions().prefixOptions(
                                    new BsonDocument()
                                            .append("strMinQueryLength", new BsonInt32(2))
                                            .append("strMaxQueryLength", new BsonInt32(10))
                            ).caseSensitive(true).diacriticSensitive(true))
                            .contentionFactor(0L));

                    BsonDocument filter = new BsonDocument("$expr", new BsonDocument("$encStrStartsWith", new BsonDocument("input", new BsonString("$secret")).append("prefix", queryPayload)));

                    // Read it back with auto-decryption
                    System.out.println("Encrypted client find (auto-decrypts):");
                    System.out.println(coll.find(filter)
                            .projection(Projections.fields(Projections.excludeId(), Projections.exclude("__safeContent__")))
                            .first().toJson());
                }
            }
        }
    }
}
