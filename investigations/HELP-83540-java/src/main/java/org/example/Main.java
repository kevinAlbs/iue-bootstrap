package org.example;

import com.mongodb.ClientEncryptionSettings;
import com.mongodb.ConnectionString;
import com.mongodb.MongoClientSettings;
import com.mongodb.client.model.vault.DataKeyOptions;
import com.mongodb.client.vault.ClientEncryption;
import com.mongodb.client.vault.ClientEncryptions;
import org.bson.BsonBinary;
import org.bson.BsonDocument;
import org.bson.BsonString;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Main {

    public static void main(final String[] args) {

        var connectionString = new ConnectionString(System.getenv("MONGODB_URI"));

        Map<String, Map<String, Object>> kmsProviders = new HashMap<String, Map<String, Object>>() {{
            put("azure", new HashMap<String, Object>() {{
                put("accessToken", System.getenv("AZURE_ACCESS_TOKEN"));
            }});
        }};

        String keyVaultNamespace = "admin.datakeys";

        // Create a data key
        {
            ClientEncryptionSettings clientEncryptionSettings = ClientEncryptionSettings.builder()
                    .keyVaultMongoClientSettings(MongoClientSettings.builder()
                            .applyConnectionString(connectionString)
                            .build())
                    .keyVaultNamespace(keyVaultNamespace)
                    .kmsProviders(kmsProviders)
                    .build();

            ClientEncryption clientEncryption = ClientEncryptions.create(clientEncryptionSettings);

            BsonDocument masterKeyProperties = new BsonDocument();
            masterKeyProperties.put("provider", new BsonString("azure"));
            masterKeyProperties.put("keyName", new BsonString("key-name-csfle"));
            masterKeyProperties.put("keyVaultEndpoint", new BsonString("key-vault-csfle.vault.azure.net"));

            BsonBinary dataKeyId = clientEncryption.createDataKey("azure", new DataKeyOptions().masterKey(masterKeyProperties));
            String base64DataKeyId = Base64.getEncoder().encodeToString(dataKeyId.getData());
            System.out.println("DataKeyId [base64]: " + base64DataKeyId);
            clientEncryption.close();
        }

    }
}