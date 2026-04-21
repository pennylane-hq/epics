require 'spec_helper'

describe Epics::Error::BusinessError do
  subject { Epics::Error::BusinessError.new(code) }

  before do
    stub_const("Epics::Error::BusinessError::ERRORS", {
      "123" => {
        "symbol" => "BOTTMUEHLE",
        "short_text" => "home of awesome",
      }
    })
  end

  let(:code) { '123' }

  describe '#to_s' do
    it 'returns a message composed of symbol and short text' do
      expect(subject.to_s).to eql('BOTTMUEHLE - home of awesome')
    end
  end

  describe '#code' do
    it 'returns the code' do
      expect(subject.code).to eql('123')
    end
  end

  describe '#symbol' do
    it 'returns the symbol' do
      expect(subject.symbol).to eql('BOTTMUEHLE')
    end
  end

  describe '#short_text' do
    it 'returns the short text' do
      expect(subject.short_text).to eql('home of awesome')
    end
  end
end

describe 'Epics::Error cross-class fallback' do
  describe Epics::Error::TechnicalError do
    context 'when code exists only in BusinessError::ERRORS' do
      subject { described_class.new('091210') }

      it 'returns the correct symbol from BusinessError' do
        expect(subject.to_s).to start_with('EBICS_X509_WRONG_KEY_USAGE')
      end

      it 'exposes the correct code' do
        expect(subject.code).to eq('091210')
      end
    end

    context 'when code exists in both ERRORS hashes (091002)' do
      subject { described_class.new('091002') }

      it 'uses TechnicalError meaning, not BusinessError' do
        expect(subject.to_s).to start_with('EBICS_INVALID_USER_OR_USER_STATE')
      end
    end

    context 'when code is unknown in both hashes' do
      subject { described_class.new('999999') }

      it 'returns EPICS_UNKNOWN' do
        expect(subject.to_s).to eq('EPICS_UNKNOWN - unknown')
      end
    end
  end

  describe Epics::Error::BusinessError do
    context 'when code exists only in TechnicalError::ERRORS' do
      subject { described_class.new('061001') }

      it 'returns the correct symbol from TechnicalError' do
        expect(subject.to_s).to start_with('EBICS_AUTHENTICATION_FAILED')
      end

      it 'exposes the correct code' do
        expect(subject.code).to eq('061001')
      end
    end

    context 'when code is unknown in both hashes' do
      subject { described_class.new('999999') }

      it 'returns EPICS_UNKNOWN' do
        expect(subject.to_s).to eq('EPICS_UNKNOWN - unknown')
      end
    end
  end
end
