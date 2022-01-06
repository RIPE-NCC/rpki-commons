package net.ripe.rpki.commons.crypto.cms;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.ContentInfo;

/**
 * <a href="http://tools.ietf.org/html/rfc5652#section-3">RFC 5652</a> ContentInfo, and 
 * <a href="http://tools.ietf.org/html/rfc5652#section-5.2">RFC 5652</a> EncapsulatedContentInfo objects.
 *
 * <pre>
 * ContentInfo ::= SEQUENCE {
 *     contentType ContentType,
 *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
 * }
 *
 * EncapsulatedContentInfo ::= SEQUENCE {
 *     eContentType ContentType,
 *     eContent [0] EXPLICIT OCTET STRING OPTIONAL
 * }
 * </pre>
 */
public class RPKIContentInfo
    extends ContentInfo
{
    private ASN1ObjectIdentifier contentType;
    private ASN1Encodable        content;

    /**
     * Return an ContentInfo object from the given object.
     * <p>
     * Accepted inputs:
     * <ul>
     * <li> null &rarr; null
     * <li> {@link RPKIContentInfo} object
     * <li> {@link ASN1Sequence#getInstance(Object) ASN1Sequence} input formats with ContentInfo structure inside
     * </ul>
     *
     * @param obj the object we want converted.
     * @exception IllegalArgumentException if the object cannot be converted.
     */
    public static RPKIContentInfo getInstance(
        Object obj) {
        if (obj instanceof RPKIContentInfo) {
            return (RPKIContentInfo) obj;
        } else if (obj != null) {
            return RPKIContentInfo.getInstance(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static RPKIContentInfo getInstance(
        ASN1TaggedObject obj,
        boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    /**
     * @deprecated use getInstance()
     */
    @Deprecated
    public RPKIContentInfo(ASN1Sequence seq) {
        super(seq);
        if (seq.size() < 1 || seq.size() > 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }

        contentType = (ASN1ObjectIdentifier) seq.getObjectAt(0);

        if (seq.size() > 1) {
            ASN1TaggedObject tagged = (ASN1TaggedObject) seq.getObjectAt(1);
            if (!tagged.isExplicit() || tagged.getTagNo() != 0) {
                throw new IllegalArgumentException("Bad tag for 'content'");
            }

            content = tagged.getObject();
        }
    }

    public RPKIContentInfo(
        ASN1ObjectIdentifier contentType,
        ASN1Encodable        content)
    {
        super(contentType, content);
        this.contentType = contentType;
        this.content = content;
    }

    @Override
    public ASN1ObjectIdentifier getContentType()
    {
        return contentType;
    }

    @Override
    public ASN1Encodable getContent()
    {
        return content;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(contentType);

        if (content != null) {
            v.add(new DERTaggedObject(0, content));
        }

        return new DERSequence(v);
    }
}
