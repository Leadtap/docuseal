# frozen_string_literal: true

# LeadTap: auto-login for EA Sign's embedded editor.
#
#   GET /ea_sso?token=<JWT>
#
# EA Sign's server checks that its (Core-authenticated) user may see the template,
# then mints a short-lived, single-use HS256 ticket signed with EA_SIGN_SSO_SECRET:
#
#   { tid: <template id>, jti: <uuid>, sub: <EA Sign user id>, cc: <company code>, exp: <now + 60s> }
#
# If a DocuSeal user holds the ticket's company code (Settings → Users → "EA Sign
# company codes"), this signs the browser in as that user, locks the session to the
# template (EaSsoLockMiddleware) and opens its editor. Otherwise it signs nobody in
# and shows DocuSeal's normal login page, returning to the editor after login.
# Without EA_SIGN_SSO_SECRET the route does not exist (404).
class EaSsoController < ActionController::Base
  include Devise::Controllers::Helpers

  SESSION_TTL = 8.hours
  REPLAY_TTL = 5.minutes

  def show
    secret = self.class.secret
    return head :not_found if secret.blank?

    payload = JWT.decode(params[:token].to_s, secret, true, algorithm: 'HS256', required_claims: %w[exp jti tid])[0]

    # Single use: a ticket leaked from a URL or log cannot be replayed.
    first_use = self.class.replay_store.write("ea_sso:jti:#{payload['jti']}", true,
                                              expires_in: REPLAY_TTL, unless_exist: true)
    return refuse('This sign-in link has already been used.') unless first_use

    template = Template.where(archived_at: nil).find_by(id: payload['tid'].to_i)
    return refuse('That document is not available.') unless template

    # Drop any earlier session (a normal login, or a lock on another template).
    reset_session

    user = EaSignCompanyCodes.user_for(template.account, payload['cc'])
    unless user
      # No user for this company: the normal DocuSeal login, then this editor.
      store_location_for(:user, "/templates/#{template.id}/edit")
      return redirect_to new_user_session_path
    end

    sign_in(user)
    session[EaSsoLockMiddleware::SESSION_KEY] = { 'tid' => template.id, 'exp' => SESSION_TTL.from_now.to_i }

    redirect_to "/templates/#{template.id}/edit"
  rescue JWT::DecodeError
    refuse('This sign-in link is invalid or has expired. Open the document again from EA Sign.')
  end

  def self.secret
    ENV.fetch('EA_SIGN_SSO_SECRET', '')
  end

  # Rails.cache, unless it is a NullStore (development/test default), which would
  # accept every ticket as "first use".
  def self.replay_store
    return Rails.cache unless Rails.cache.is_a?(ActiveSupport::Cache::NullStore)

    @replay_store ||= ActiveSupport::Cache::MemoryStore.new
  end

  private

  def refuse(message)
    render html: ERB::Util.html_escape(message), status: :forbidden
  end
end
