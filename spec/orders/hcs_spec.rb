RSpec.describe Epics::HCS do
  let(:client) { Epics::Client.new(key, 'secret', 'https://194.180.18.30/ebicsweb/ebicsweb', 'SIZBN001', 'EBIX', 'EBICS') }
  let(:key) { File.read(File.join(File.dirname(__FILE__), '..', 'fixtures', 'SIZBN001.key')) }

  subject { described_class.new(client) }

  describe '#initialize' do
    it 'inherits from GenericUploadRequest' do
      expect(subject).to be_a(Epics::GenericUploadRequest)
    end

    it 'sets order_data option to true' do
      expect(subject.options[:order_data]).to be true
    end

    it 'generates order data document' do
      expect(subject.document).to include('HCSRequestOrderData')
    end
  end

  describe '#header' do
    let(:header) { subject.header }

    it 'returns a header request with correct order type' do
      expect(header.to_xml).to include('HCS')
    end

    it 'sets correct order attribute' do
      expect(header.to_xml).to include('OZHNN')
    end

    it 'sets num_segments to 1' do
      expect(header.to_xml).to include('<NumSegments>1</NumSegments>')
    end

    it 'sets transaction phase to Initialisation' do
      expect(header.to_xml).to include('Initialisation')
    end
  end

  describe '#order_data' do
    subject(:order_data) { described_class.new(client).send(:order_data, client) }

    it 'includes HCSRequestOrderData root element' do
      expect(order_data).to include('<HCSRequestOrderData')
    end

    it 'includes correct namespaces' do
      expect(order_data).to include('xmlns:esig="http://www.ebics.org/S001"')
      expect(order_data).to include('xmlns:ds="http://www.w3.org/2000/09/xmldsig#"')
    end

    it 'includes AuthenticationPubKeyInfo section' do
      expect(order_data).to include('<AuthenticationPubKeyInfo>')
      expect(order_data).to include('<AuthenticationVersion>X002</AuthenticationVersion>')
    end

    it 'includes EncryptionPubKeyInfo section' do
      expect(order_data).to include('<EncryptionPubKeyInfo>')
      expect(order_data).to include('<EncryptionVersion>E002</EncryptionVersion>')
    end

    it 'includes SignaturePubKeyInfo section' do
      expect(order_data).to include('<SignaturePubKeyInfo>')
      expect(order_data).to include('<SignatureVersion>A006</SignatureVersion>')
    end

    it 'includes RSA key values for all three keys' do
      expect(order_data).to include('<ds:RSAKeyValue>')
      expect(order_data).to include('<ds:Modulus>')
      expect(order_data).to include('<ds:Exponent>')
    end

    it 'includes partner and user IDs' do
      expect(order_data).to include('<PartnerID>EBICS</PartnerID>')
      expect(order_data).to include('<UserID>EBIX</UserID>')
    end

    describe 'validate against fixture' do
      let(:hcs_request_order_data) do
        Nokogiri::XML(File.read(File.join(File.dirname(__FILE__), '..', 'fixtures', 'xml',
                                          'hcs_request_order_data.xml')))
      end

      it 'will match exactly' do
        expect(Nokogiri::XML(order_data)).to be_equivalent_to(hcs_request_order_data)
      end
    end

    context 'with x509 certificates' do
      let(:client) do
        client = Epics::Client.new(key, 'secret', 'https://194.180.18.30/ebicsweb/ebicsweb', 'SIZBN001', 'EBIX',
                                   'EBICS')
        client.x_509_certificate_x_content = generate_x_509_crt(client.x.key, distinguished_name)
        client.x_509_certificate_e_content = generate_x_509_crt(client.e.key, distinguished_name)
        client.x_509_certificate_a_content = generate_x_509_crt(client.a.key, distinguished_name)
        client
      end
      let(:distinguished_name) { '/C=GB/O=TestOrg/CN=test.example.org' }
      let(:x_crt) { Epics::X509Certificate.new(client.x_509_certificate_x_content) }
      let(:e_crt) { Epics::X509Certificate.new(client.x_509_certificate_e_content) }
      let(:a_crt) { Epics::X509Certificate.new(client.x_509_certificate_a_content) }

      it 'includes x509 certificate for authentication key' do
        expect(order_data).to include('<ds:X509IssuerName>/C=GB/O=TestOrg/CN=test.example.org</ds:X509IssuerName>')
        expect(order_data).to include("<ds:X509SerialNumber>#{x_crt.serial}</ds:X509SerialNumber>")
        expect(order_data).to include("<ds:X509Certificate>#{x_crt.data}</ds:X509Certificate>")
      end

      it 'includes x509 certificate for encryption key' do
        expect(order_data).to include("<ds:X509Certificate>#{e_crt.data}</ds:X509Certificate>")
      end

      it 'includes x509 certificate for signature key' do
        expect(order_data).to include("<ds:X509Certificate>#{a_crt.data}</ds:X509Certificate>")
      end

      it 'uses correct serial number for all certificates' do
        # NOTE: There's a potential bug in the original code - it uses x_509_certificate_x.version
        # for all three certificates instead of their respective versions
        expect(order_data).to include("<ds:X509SerialNumber>#{a_crt.serial}</ds:X509SerialNumber>")
        expect(order_data).to include("<ds:X509SerialNumber>#{x_crt.serial}</ds:X509SerialNumber>")
        expect(order_data).to include("<ds:X509SerialNumber>#{e_crt.serial}</ds:X509SerialNumber>")
      end
    end

    context 'without x509 certificates' do
      it 'does not include X509Data sections' do
        expect(order_data).not_to include('<ds:X509Data>')
      end

      it 'still includes PubKeyValue sections' do
        expect(order_data).to include('<PubKeyValue>')
        expect(order_data).to include('<PubKeyValue>')
      end
    end
  end

  describe 'RSA key encoding' do
    let(:order_data) { described_class.new(client).send(:order_data, client) }

    it 'properly encodes modulus values' do
      expect(order_data).to match(%r{<ds:Modulus>[A-Za-z0-9+/=]+</ds:Modulus>})
    end

    it 'properly encodes exponent values' do
      expect(order_data).to match(%r{<ds:Exponent>[A-Za-z0-9+/=]+</ds:Exponent>})
    end
  end

  context 'when EBICS version is 2.4' do
    let(:client) do
      Epics::Client.new(key, 'secret', 'https://194.180.18.30/ebicsweb/ebicsweb', 'SIZBN001', 'EBIX', 'EBICS', options)
    end
    let(:options) { { version: Epics::Keyring::VERSION_24 } }
    let(:order_data) { described_class.new(client).send(:order_data, client) }

    it 'does not include OrderID in the headers' do
      expect(subject.header.to_xml).not_to include('<OrderID>')
    end

    it 'includes the correct urn schema and version' do
      expect(subject.to_xml).to include('xmlns="http://www.ebics.org/H003"')
      expect(subject.to_xml).to include('Version="H003"')
    end

    it 'uses correct namespace in order data' do
      expect(order_data).to include('xmlns="http://www.ebics.org/H003"')
    end
  end

  context 'when EBICS version is 2.5' do
    let(:order_data) { described_class.new(client).send(:order_data, client) }

    it 'does not include the OrderID in the headers' do
      expect(subject.header.to_xml).not_to include('<OrderID>A001</OrderID>')
    end

    it 'includes the correct urn schema' do
      expect(subject.to_xml).to include('xmlns="urn:org:ebics:H004"')
      expect(subject.to_xml).to include('Version="H004"')
    end

    it 'uses correct namespace in order data' do
      expect(order_data).to include('xmlns="urn:org:ebics:H004"')
    end
  end

  describe 'inheritance behavior' do
    it 'has encrypted order data' do
      expect(subject.encrypted_order_data).to match(%r{^[A-Za-z0-9+/=]+$})
    end

    it 'has encrypted order signature' do
      expect(subject.encrypted_order_signature).to match(%r{^[A-Za-z0-9+/=]+$})
    end

    it 'generates proper body XML' do
      body = subject.body
      expect(body.to_xml).to include('<DataTransfer>')
      expect(body.to_xml).to include('<DataEncryptionInfo')
      expect(body.to_xml).to include('<SignatureData')
    end
  end
end
