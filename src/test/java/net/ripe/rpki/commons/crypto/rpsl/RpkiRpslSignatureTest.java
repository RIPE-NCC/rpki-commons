package net.ripe.rpki.commons.crypto.rpsl;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.assertEquals;

public class RpkiRpslSignatureTest {

    private final String SIGNATURE_STRING = "v=rpkiv1; c=rsync://.....; m=sha256WithRSAEncryption;" +
            "t=2014-12-31T23:59:60Z;\n" +
            "a=attribute1+attribute2+attribute3;\n" +
            "b=<base64 data>";

    @Test
    public void should_parse_signature_line() {
        RpkiRpslSignature signature = RpkiRpslSignature.parse(this.SIGNATURE_STRING);
        assertEquals("rpkiv1", signature.getValue("v"));
    }

    @Test
    public void should_extract_signed_attributes_field() {
        RpkiRpslSignature signature = RpkiRpslSignature.parse(this.SIGNATURE_STRING);
        List<String> signedAttributes = signature.getSignedAttributes();
        assertEquals("attribute1", signedAttributes.get(0));
        assertEquals("attribute2", signedAttributes.get(1));
        assertEquals("attribute3", signedAttributes.get(2));
    }

}
