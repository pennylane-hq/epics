# frozen_string_literal: true

class Epics::FDL < Epics::GenericRequest
  attr_accessor :file_format

  def initialize(client, file_format)
    super(client)
    self.file_format = file_format
  end

  def header
    Nokogiri::XML::Builder.new do |xml|
      xml.header(authenticate: true) do
        xml.static do
          xml.HostID host_id
          xml.Nonce nonce
          xml.Timestamp timestamp
          xml.PartnerID partner_id
          xml.UserID user_id
          xml.Product('EPICS - a ruby ebics kernel', 'Language' => 'de')
          xml.OrderDetails do
            xml.OrderType 'FDL'
            xml.OrderID 'A00A'
            xml.OrderAttribute 'DZHNN'
            xml.FDLOrderParams do
              xml.FileFormat file_format
            end
          end
          xml.BankPubKeyDigests do
            xml.Authentication(client.bank_x.public_digest, Version: 'X002', Algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256')
            xml.Encryption(client.bank_e.public_digest, Version: 'E002',
                                                        Algorithm: 'http://www.w3.org/2001/04/xmlenc#sha256')
          end
          xml.SecurityMedium '0000'
        end
        xml.mutable do
          xml.TransactionPhase 'Initialisation'
        end
      end
    end.doc.root
  end
end
