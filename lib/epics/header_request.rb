class Epics::HeaderRequest
  extend Forwardable
  attr_accessor :client

  def initialize(client)
    self.client = client
  end

  def_delegators :client, :host_id, :user_id, :partner_id

  def build(options = {})
    options[:with_bank_pubkey_digests] = true if options[:with_bank_pubkey_digests].nil?

    Nokogiri::XML::Builder.new do |xml|
      xml.header(authenticate: true) do
        xml.static do
          xml.HostID host_id
          xml.Nonce options[:nonce] if options[:nonce]
          xml.Timestamp options[:timestamp] if options[:timestamp]
          xml.PartnerID partner_id
          xml.UserID user_id
          xml.Product(client.product_name, 'Language' => client.locale)
          xml.OrderDetails do
            xml.OrderType options[:order_type]
            if client.version == Epics::Keyring::VERSION_24 && options[:order_type] != 'HCS'
              xml.OrderID b36encode(client.next_order_id)
            end
            xml.OrderAttribute options[:order_attribute]
            if options[:order_params]
              xml.StandardOrderParams do
                build_attributes(xml, options[:order_params])
              end
            end
            build_attributes(xml, options[:custom_order_params]) if options[:custom_order_params]
          end
          if options[:with_bank_pubkey_digests]
            xml.BankPubKeyDigests do
              xml.Authentication(client.bank_x.public_digest, Version: 'X002', Algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256')
              xml.Encryption(client.bank_e.public_digest, Version: 'E002', Algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256')
            end
          end
          xml.SecurityMedium '0000'
          xml.NumSegments options[:num_segments] if options[:num_segments]
        end
        if options[:mutable]
          xml.mutable do
            build_attributes(xml, options[:mutable])
          end
        end
      end
    end.doc.root
  end

  private

  def build_attributes(xml, attributes)
    attributes.each do |key, value|
      if value.is_a?(Hash)
        xml.send(key) do
          build_attributes(xml, value)
        end
      else
        xml.send(key, value)
      end
    end
  end

  def b36encode(number)
    number.to_s(36).upcase.rjust(4, '0')
  end
end
