plugins {
    id("application")
}

group = "quickstart"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.mongodb:mongodb-driver-sync:5.9.0")
    implementation("org.mongodb:mongodb-crypt:5.9.0")
}

application {
    mainClass.set("quickstart.ExplicitEncrypt")
}
