class Epics::INI < Epics::GenericRequest
  def root
    "ebicsUnsecuredRequest"
  end

  def header
    client.header_request.build(
      order_type: 'INI',
      order_attribute: 'DZNNN',
      with_bank_pubkey_digests: false,
      mutable: {},
    )
  end

  def body
    Nokogiri::XML::Builder.new do |xml|
      xml.body{
        xml.DataTransfer {
          xml.OrderData Base64.strict_encode64(Zlib::Deflate.deflate(key_signature))
        }
      }
    end.doc.root
  end

  def key_signature
    x_509_certificate_a = client.x_509_certificate_a

    Nokogiri::XML::Builder.new do |xml|
      xml.SignaturePubKeyOrderData('xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#', 'xmlns' => 'http://www.ebics.org/S001') {
        xml.SignaturePubKeyInfo {
          if x_509_certificate_a
            xml.send('ds:X509Data') do
              xml.send('ds:X509IssuerSerial') do
                xml.send('ds:X509IssuerName', x_509_certificate_a.issuer )
                xml.send('ds:X509SerialNumber', x_509_certificate_a.version)
              end
              xml.send('ds:X509Certificate', x_509_certificate_a.data)
            end
          end
          xml.PubKeyValue {
            xml.send('ds:RSAKeyValue') {
              xml.send('ds:Modulus', Base64.strict_encode64([client.a.n].pack("H*")))
              xml.send('ds:Exponent', Base64.strict_encode64(client.a.key.e.to_s(2)))
            }
            xml.TimeStamp timestamp
          }
          xml.SignatureVersion 'A006'
        }
        xml.PartnerID partner_id
        xml.UserID user_id
      }
    end.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML, encoding: 'utf-8')
  end

  def to_xml
    Nokogiri::XML::Builder.new do |xml|
      xml.send(root, 'xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#', 'xmlns' => client.urn_schema, 'Version' => client.version, 'Revision' => '1') {
        xml.parent.add_child(header)
        xml.parent.add_child(body)
      }
    end.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML, encoding: 'utf-8')
  end
end
