package net.ripe.rpki.commons.validation.interop;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertTrue;

public class BBNConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseAllObjects() throws IOException {
        var objectCount = new AtomicInteger();
        var errorCount = new AtomicInteger();
        var exceptionCount = new AtomicInteger();

        var extensionMatcher = FileSystems.getDefault().getPathMatcher("glob:**.{cer,crl,mft,roa}");

        try (Stream<Path> paths = Files.find(new File(PATH_TO_BBN_OBJECTS).toPath(), Integer.MAX_VALUE, (p, attr) -> extensionMatcher.matches(p))) {
            paths.forEach(path -> {
                objectCount.incrementAndGet();
                try {
                    byte[] encoded = Files.readAllBytes(path);
                    ValidationResult result = ValidationResult.withLocation(path.getFileName().toString());

                    final CertificateRepositoryObject res = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, result);
                    // Check that invariant that "parsing errors or result" holds.
                    assertThat(result.hasFailures() || res != null).isTrue();

                    if (result.hasFailures() && path.getFileName().startsWith("good")) {
                        System.err.println("Supposed to be good: " + path.getFileName());
                        errorCount.incrementAndGet();
                    } else if (!result.hasFailures() && path.getFileName().startsWith("bad")) {
                        System.err.println("Supposed to be bad: " + path.getFileName());
                        errorCount.incrementAndGet();
                    } else {
                        System.out.println(path.getFileName() + " -> " + result.hasFailures());
                    }
                } catch (IOException | RuntimeException ex) {
                    System.err.println("Exception while parsing " + path.getFileName());
                    exceptionCount.incrementAndGet();
                }
            });
        }

        System.out.println(objectCount + " objects: " + errorCount + " errors, " + exceptionCount + " exceptions");
    }
}
