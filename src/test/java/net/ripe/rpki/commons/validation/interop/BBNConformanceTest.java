package net.ripe.rpki.commons.validation.interop;

import com.google.common.io.Files;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.ghostbuster.GhostbustersCmsParser;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCmsParser;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsParser;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.crypto.util.CertificateRepositoryObjectFactory;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateParser;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import static org.junit.Assert.assertTrue;

public class BBNConformanceTest {

    private static final String PATH_TO_BBN_OBJECTS = "src/test/resources/conformance/";

    @Test
    public void shouldParseAllObjects() throws IOException {
        int objectCount = 0;
        int errorCount = 0;
        int exceptionCount = 0;

        Iterator<File> fileIterator = FileUtils.iterateFiles(new File(PATH_TO_BBN_OBJECTS), new String[]{"cer", "crl", "mft", "roa"}, true);
        while (fileIterator.hasNext()) {
            objectCount++;
            File file = fileIterator.next();
            byte[] encoded = Files.toByteArray(file);
            ValidationResult result = ValidationResult.withLocation(file.getName());

            try {
                final CertificateRepositoryObject res = CertificateRepositoryObjectFactory.createCertificateRepositoryObject(encoded, result);
                // Check that invariant that "parsing errors or result" holds.
                assertTrue(result.hasFailures() || res != null);

                if (result.hasFailures() && file.getName().startsWith("good")) {
                    System.err.println("Supposed to be good: " + file.getName());
                    errorCount++;
                } else if (! result.hasFailures() && file.getName().startsWith("bad")) {
                    System.err.println("Supposed to be bad: " + file.getName());
                    errorCount++;
                } else {
                    System.out.println(file.getName() + " -> " + result.hasFailures());
                }
            } catch (RuntimeException ex) {
                System.err.println("Exception while parsing " + file.getName() );
                exceptionCount++;
            }
        }

        System.out.println(objectCount + " objects: " + errorCount + " errors, " + exceptionCount + " exceptions");
    }
}
