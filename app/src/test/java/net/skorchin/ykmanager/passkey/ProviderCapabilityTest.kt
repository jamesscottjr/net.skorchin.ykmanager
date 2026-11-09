package net.skorchin.ykmanager.passkey

import androidx.credentials.PublicKeyCredential
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Android filters providers by capability string. If the passkey type that
 * androidx.credentials puts on requests isn't declared, the provider is never
 * asked, even when it's the phone's default passkey service.
 */
class ProviderCapabilityTest {
    @Test
    fun declaresTheRequestTypeUsedByCredentialManager() {
        val file = listOf("src/main/res/xml/passkey_provider.xml", "app/src/main/res/xml/passkey_provider.xml")
            .map(::File).first { it.exists() }
        val doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(file)
        val nodes = doc.getElementsByTagName("capability")
        val names = (0 until nodes.length).map { nodes.item(it).attributes.getNamedItem("name").nodeValue }
        assertTrue("capabilities were $names", PublicKeyCredential.TYPE_PUBLIC_KEY_CREDENTIAL in names)
    }
}
