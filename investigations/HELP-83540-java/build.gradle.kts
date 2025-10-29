plugins {
    id("java")
}

group = "org.example"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    testImplementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
    // https://mvnrepository.com/artifact/org.mongodb/mongodb-crypt
    implementation("org.mongodb:mongodb-crypt:5.6.1")
    // https://mvnrepository.com/artifact/org.mongodb/mongodb-driver-sync
    implementation("org.mongodb:mongodb-driver-sync:5.6.1")
}

tasks.test {
    useJUnitPlatform()
}