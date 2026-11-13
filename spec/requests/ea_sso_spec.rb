# frozen_string_literal: true

# LeadTap: EA Sign editor auto-login (EaSsoController) and the session lock
# (EaSsoLockMiddleware) that confines it to one template.
describe 'EA Sign editor auto-login' do
  let(:account) { create(:account) }
  let(:user) { create(:user, account:) }
  let(:template) { create(:template, account:, author: user) }
  let(:other_template) { create(:template, account:, author: user) }
  let(:secret) { 'test-ea-sign-sso-secret' }

  before do
    allow(EaSsoController).to receive_messages(secret:, replay_store: ActiveSupport::Cache::MemoryStore.new)
  end

  def ticket(tid: template.id, exp: 60.seconds.from_now.to_i, jti: SecureRandom.uuid, key: secret, cc: nil)
    JWT.encode({ 'tid' => tid, 'exp' => exp, 'jti' => jti, 'sub' => 'A00001', 'cc' => cc }.compact, key, 'HS256')
  end

  let!(:company_user) { create(:user, account:, email: 'maskells@example.com') }

  before { EaSignCompanyCodes.save!(company_user, %w[MASK]) }

  def open_editor
    get '/ea_sso', params: { token: ticket(cc: 'MASK') }
    expect(response).to redirect_to("/templates/#{template.id}/edit")
  end

  describe 'GET /ea_sso' do
    it 'signs in and opens the template editor' do
      open_editor
      get "/templates/#{template.id}/edit"
      expect(response).to have_http_status(:ok)
    end

    it 'is 404 when EA_SIGN_SSO_SECRET is not set' do
      allow(EaSsoController).to receive(:secret).and_return('')
      get '/ea_sso', params: { token: ticket }
      expect(response).to have_http_status(:not_found)
    end

    it 'refuses a ticket signed with another key' do
      get '/ea_sso', params: { token: ticket(key: 'wrong') }
      expect(response).to have_http_status(:forbidden)
    end

    it 'refuses an expired ticket' do
      get '/ea_sso', params: { token: ticket(exp: 1.minute.ago.to_i) }
      expect(response).to have_http_status(:forbidden)
    end

    it 'refuses a ticket used twice' do
      token = ticket(cc: 'MASK')
      get '/ea_sso', params: { token: }
      expect(response).to have_http_status(:redirect)
      reset!
      get '/ea_sso', params: { token: }
      expect(response).to have_http_status(:forbidden)
    end

    it 'refuses an archived template' do
      template.update!(archived_at: Time.current)
      get '/ea_sso', params: { token: ticket }
      expect(response).to have_http_status(:forbidden)
    end
  end

  describe 'a locked session' do
    before { open_editor }

    it 'may use its own template' do
      get "/templates/#{template.id}"
      expect(response).not_to have_http_status(:forbidden)
    end

    it 'may not open another template' do
      get "/templates/#{other_template.id}/edit"
      expect(response).to have_http_status(:forbidden)
    end

    it 'may not open the dashboard' do
      get '/'
      expect(response).to have_http_status(:forbidden)
    end

    it 'may not use the JSON API with the session cookie' do
      get '/api/templates'
      expect(response).to have_http_status(:forbidden)
    end

    it 'may not delete its template' do
      delete "/templates/#{template.id}"
      expect(response).to have_http_status(:forbidden)
      expect(template.reload.archived_at).to be_nil
    end

    it 'may not clone or re-folder its template' do
      get "/templates/#{template.id}/clone/new"
      expect(response).to have_http_status(:forbidden)
      get "/templates/#{template.id}/folder/edit"
      expect(response).to have_http_status(:forbidden)
    end

    it 'moves to another template when a new ticket is opened' do
      get '/ea_sso', params: { token: ticket(tid: other_template.id, cc: 'MASK') }
      expect(response).to redirect_to("/templates/#{other_template.id}/edit")
      get "/templates/#{other_template.id}/edit"
      expect(response).to have_http_status(:ok)
      get "/templates/#{template.id}/edit"
      expect(response).to have_http_status(:forbidden)
    end

    it 'ends after its expiry' do
      travel_to 9.hours.from_now do
        get "/templates/#{template.id}/edit"
        expect(response).to have_http_status(:forbidden)
      end
    end
  end

  describe 'which DocuSeal user the company works as' do
    it 'signs in as the user holding the company code' do
      expect(EaSignCompanyCodes.user_for(account, 'mask')).to eq(company_user)
      get '/ea_sso', params: { token: ticket(cc: 'mask') }
      expect(response).to redirect_to("/templates/#{template.id}/edit")
      expect(company_user.reload.sign_in_count).to eq(1)
    end

    it 'shows the normal login page when no user has the code, then returns to the editor' do
      get '/ea_sso', params: { token: ticket(cc: 'NONE') }
      expect(response).to redirect_to('/sign_in')
      get "/templates/#{template.id}/edit"
      expect(response).to redirect_to('/sign_in')
      expect(user.reload.sign_in_count).to eq(0)
    end

    it 'shows the normal login page when the ticket has no company code' do
      get '/ea_sso', params: { token: ticket }
      expect(response).to redirect_to('/sign_in')
    end

    it 'ignores archived users' do
      company_user.update!(archived_at: Time.current)
      expect(EaSignCompanyCodes.user_for(account, 'MASK')).to be_nil
    end

    it 'finds codes already held by another user' do
      expect(EaSignCompanyCodes.taken_by_others(user, %w[MASK OTHER]).keys).to eq(%w[MASK])
    end
  end

  it 'leaves normal sessions alone' do
    sign_in(user)
    get "/templates/#{other_template.id}/edit"
    expect(response).to have_http_status(:ok)
  end

  describe EaSsoLockMiddleware do
    it 'allows editor requests and shared assets, nothing else' do
      allowed = ->(method, path) { described_class.allowed?(method, path, 7) }

      expect(allowed.call('GET', '/templates/7/edit')).to be(true)
      expect(allowed.call('PUT', '/templates/7')).to be(true)
      expect(allowed.call('POST', '/templates/7/documents')).to be(true)
      expect(allowed.call('POST', '/templates/7/submissions')).to be(true)
      expect(allowed.call('GET', '/preview/abc123')).to be(true)
      expect(allowed.call('POST', '/direct_uploads')).to be(true)
      expect(allowed.call('DELETE', '/sign_out')).to be(true)

      expect(allowed.call('DELETE', '/templates/7')).to be(false)
      expect(allowed.call('GET', '/templates/70/edit')).to be(false)
      expect(allowed.call('GET', '/templates/7x/edit')).to be(false)
      expect(allowed.call('POST', '/templates/7/clone_and_replace')).to be(false)
      expect(allowed.call('GET', '/templates')).to be(false)
      expect(allowed.call('GET', '/settings/api')).to be(false)
      expect(allowed.call('GET', '/api/templates/7')).to be(false)
    end
  end
end
