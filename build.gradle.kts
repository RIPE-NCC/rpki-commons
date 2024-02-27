plugins {
    id("io.freefair.lombok") version "8.4"

    `java-library`
    `signing`
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0-rc-2"
}

repositories {
    mavenLocal()
    maven {
        url = uri("https://artefacts.ripe.net/repository/maven-releases-ncc/")
    }

    maven {
        url = uri("https://repo.maven.apache.org/maven2/")
    }
}

dependencies {
    api(libs.net.ripe.ipresource.ipresource)

    api(libs.net.sf.saxon.saxon.he)
    api(libs.org.slf4j.slf4j.api)
    api(libs.joda.time.joda.time)
    api(libs.org.apache.commons.commons.lang3)

    api(libs.org.bouncycastle.bcprov.jdk18on)
    api(libs.org.bouncycastle.bcmail.jdk18on)

    api(libs.com.google.guava.guava)
    api(libs.com.thoughtworks.xstream.xstream)

    testImplementation(libs.org.junit.jupiter.junit.jupiter)
    testImplementation(libs.org.junit.vintage.junit.vintage.engine)
    testImplementation(libs.org.assertj.assertj.core)
    testImplementation(libs.org.mockito.mockito.core)
    testImplementation(libs.org.hamcrest.hamcrest)
    testImplementation(libs.org.relaxng.jing)
    testImplementation(libs.com.pholser.junit.quickcheck.core)
    testImplementation(libs.com.pholser.junit.quickcheck.generators)
    // Used in unit tests for Equals Hashcode tests.
    testImplementation(libs.com.google.guava.guava.testlib)
    compileOnly(libs.org.projectlombok.lombok)
}

group = "net.ripe.rpki"
version = "1.37-SNAPSHOT"
description = "RPKI Commmons"

java {
    sourceCompatibility = JavaVersion.VERSION_11

    withJavadocJar()
    withSourcesJar()
}

tasks.withType<Javadoc> {
    options {
        (this as CoreJavadocOptions).addStringOption("Xdoclint:none", "-quiet")
    }
}

tasks.withType<JavaCompile>() {
    options.encoding = "UTF-8"
}

tasks.withType<Javadoc>() {
    options.encoding = "UTF-8"
}

nexusPublishing {
    repositories {
        sonatype()
    }
}

signing {
    val signingKey: String? by project
    val signingPassword: String? by project

    useInMemoryPgpKeys(signingKey, signingPassword)
    sign {
        configurations["archives"]
    }
}
