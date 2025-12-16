class Epics::HCS < Epics::GenericUploadRequest
  def initialize(client)
    document = order_data(client)
    super(client, document, order_data: true)
  end

  def header
    client.header_request.build(
      nonce: nonce,
      timestamp: timestamp,
      order_type: 'HCS',
      order_attribute: 'OZHNN',
      num_segments: 1,
      mutable: { TransactionPhase: 'Initialisation' },
      order_params: {}
    )
  end

  private

  def order_data(client)
    x_509_certificate_a = client.x_509_certificate_a
    x_509_certificate_x = client.x_509_certificate_x
    x_509_certificate_e = client.x_509_certificate_e

    Nokogiri::XML::Builder.new do |xml|
      xml.HCSRequestOrderData('xmlns' => client.urn_schema, 'xmlns:esig' => 'http://www.ebics.org/S001',
                              'xmlns:ds' => 'http://www.w3.org/2000/09/xmldsig#') do
        xml.AuthenticationPubKeyInfo do
          if x_509_certificate_x
            xml.send('ds:X509Data') do
              xml.send('ds:X509IssuerSerial') do
                xml.send('ds:X509IssuerName', x_509_certificate_x.issuer)
                xml.send('ds:X509SerialNumber', x_509_certificate_x.serial)
              end
              xml.send('ds:X509Certificate', x_509_certificate_x.data)
            end
          end
          xml.PubKeyValue do
            xml.send('ds:RSAKeyValue') do
              xml.send('ds:Modulus', Base64.strict_encode64([client.x.n].pack('H*')))
              xml.send('ds:Exponent', Base64.strict_encode64(client.x.key.e.to_s(2)))
            end
          end
          xml.AuthenticationVersion 'X002'
        end
        xml.EncryptionPubKeyInfo do
          if x_509_certificate_e
            xml.send('ds:X509Data') do
              xml.send('ds:X509IssuerSerial') do
                xml.send('ds:X509IssuerName', x_509_certificate_e.issuer)
                xml.send('ds:X509SerialNumber', x_509_certificate_e.serial)
              end
              xml.send('ds:X509Certificate', x_509_certificate_e.data)
            end
          end
          xml.PubKeyValue do
            xml.send('ds:RSAKeyValue') do
              xml.send('ds:Modulus', Base64.strict_encode64([client.e.n].pack('H*')))
              xml.send('ds:Exponent', Base64.strict_encode64(client.e.key.e.to_s(2)))
            end
          end
          xml.EncryptionVersion 'E002'
        end
        xml.SignaturePubKeyInfo do
          if x_509_certificate_a
            xml.send('ds:X509Data') do
              xml.send('ds:X509IssuerSerial') do
                xml.send('ds:X509IssuerName', x_509_certificate_a.issuer)
                xml.send('ds:X509SerialNumber', x_509_certificate_a.serial)
              end
              xml.send('ds:X509Certificate', x_509_certificate_a.data)
            end
          end
          xml.PubKeyValue do
            xml.send('ds:RSAKeyValue') do
              xml.send('ds:Modulus', Base64.strict_encode64([client.a.n].pack('H*')))
              xml.send('ds:Exponent', Base64.strict_encode64(client.a.key.e.to_s(2)))
            end
          end
          xml.SignatureVersion client.signature_version
        end
        xml.PartnerID client.partner_id
        xml.UserID client.user_id
      end
    end.to_xml(save_with: Nokogiri::XML::Node::SaveOptions::AS_XML, encoding: 'utf-8')
  end
end
