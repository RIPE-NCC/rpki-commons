/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.commons.provisioning.identity;

import javax.xml.namespace.QName;

import net.ripe.certification.client.xml.converters.URIConverter;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.converters.reflection.Sun14ReflectionProvider;
import com.thoughtworks.xstream.io.xml.QNameMap;
import com.thoughtworks.xstream.io.xml.StaxDriver;
import com.thoughtworks.xstream.io.xml.XmlFriendlyReplacer;
import com.thoughtworks.xstream.mapper.Mapper;
import com.thoughtworks.xstream.mapper.MapperWrapper;


public abstract class IdentitySerializer<T> {

    protected XStream xStream;

    protected IdentitySerializer() {

        QNameMap qNameMap = new QNameMap();

        QName parentIdQName = new QName(ParentIdentity.XMLNS, ParentIdentity.PARENT_IDENTITY_NODE_NAME);
        qNameMap.registerMapping(parentIdQName, ParentIdentity.PARENT_IDENTITY_NODE_NAME);

        QName childIdQName = new QName(ChildIdentity.XMLNS, ChildIdentity.CHILD_IDENTITY_NODE_NAME);
        qNameMap.registerMapping(childIdQName, ChildIdentity.CHILD_IDENTITY_NODE_NAME);

        XmlFriendlyReplacer replacer = new XmlFriendlyReplacer("_-", "_");

        xStream = new XStream(new Sun14ReflectionProvider(), new StaxDriver(qNameMap, replacer)) {
            @Override
            protected MapperWrapper wrapMapper(MapperWrapper next) {
                return new IgnoreUnknownFieldsMapperWrapper(next);
            }
        };
        xStream.autodetectAnnotations(true);
        xStream.processAnnotations(ParentIdentity.class);
        xStream.processAnnotations(ChildIdentity.class);
        xStream.registerConverter(new ProvisioningIdentityCertificateConverterForIdExchange());
        xStream.registerConverter(new URIConverter());
    }

    public abstract T deserialize(String xml);

    public abstract String serialize(T object);

    /**
     * Used to ignore unknown fields when deserialising XML. See <a
     * href="http://pvoss.wordpress.com/2009/01/08/xstream/">Omit Unexpected XML Elements With
     * XStream</a>.
     */
    private static final class IgnoreUnknownFieldsMapperWrapper extends MapperWrapper {
        private IgnoreUnknownFieldsMapperWrapper(Mapper wrapped) {
            super(wrapped);
        }

        @Override
        public boolean shouldSerializeMember(@SuppressWarnings("rawtypes") Class definedIn, String fieldName) {
            if (definedIn == Object.class) {
                return false;
            }
            return super.shouldSerializeMember(definedIn, fieldName);
        }
    }

}
