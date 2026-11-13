# frozen_string_literal: true

# LeadTap: confines a session opened by EA Sign's auto-login (EaSsoController) to
# the one template it was opened for.
#
# Every company shares one DocuSeal account and user, so an unrestricted session
# would show — and let anyone delete — every company's templates. A session with
# session['ea_sso'] = { 'tid' => <template id>, 'exp' => <unix time> } may only:
#
#   - use that template: /templates/<tid> and everything under it (edit, save,
#     documents, fields, preview, send) — except deleting, cloning or re-foldering it
#   - fetch what the editor loads: signed file/preview links, direct uploads, assets
#   - sign out
#
# Anything else — other templates, the dashboard, settings, the JSON API — is
# refused with 403. This runs as Rack middleware, after the session and Warden,
# so it covers every controller, including the API ones that also accept a
# session cookie. Normal (non-EA-Sign) sessions are untouched.
class EaSsoLockMiddleware
  SESSION_KEY = 'ea_sso'

  SHARED = [
    %r{\A/(packs|assets|fonts|images)/},
    %r{\A/favicon},
    %r{\A/preview/[^/]+},                    # signed page previews
    %r{\A/(file|blobs_proxy)/[^/]+/},        # signed blob proxies
    %r{\A/blobs/proxy/},
    %r{\A/disk/},                            # active storage disk service (signed)
    %r{\A/rails/active_storage/},
    %r{\A/direct_uploads\z}
  ].freeze

  # Under /templates/<tid>/…: things that leave the template or destroy it.
  BLOCKED_SUBPATHS = %r{\A/(clone|clone_and_replace|folder)(/|\z)}

  def initialize(app)
    @app = app
  end

  def call(env)
    session = env['rack.session']
    lock = session && session[SESSION_KEY]
    return @app.call(env) unless lock

    request = Rack::Request.new(env)

    if lock['exp'].to_i < Time.now.to_i
      session.clear
      return @app.call(env) if request.path_info == '/ea_sso'

      return refuse('Your EA Sign editor session has ended. Open the document again from EA Sign.')
    end

    return @app.call(env) if self.class.allowed?(request.request_method, request.path_info, lock['tid'].to_i)

    refuse('Only the document opened from EA Sign is available here.')
  end

  def self.allowed?(method, path, tid)
    # A new EA Sign ticket (another document) replaces this session's lock;
    # EaSsoController verifies it and resets the session.
    return true if path == '/ea_sso' && method == 'GET'
    return true if path == '/sign_out'
    return true if SHARED.any? { |re| re.match?(path) }

    prefix = "/templates/#{tid}"
    return false unless path == prefix || path.start_with?("#{prefix}/")

    rest = path.delete_prefix(prefix)
    return false if rest.empty? && method == 'DELETE'

    !BLOCKED_SUBPATHS.match?(rest)
  end

  private

  def refuse(message)
    body = <<~HTML
      <!doctype html><html><head><meta charset="utf-8"><title>Not available</title></head>
      <body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#374151">
      <p>#{ERB::Util.html_escape(message)}</p></body></html>
    HTML
    [403, { 'content-type' => 'text/html; charset=utf-8', 'cache-control' => 'no-store' }, [body]]
  end
end
