# frozen_string_literal: true

# LeadTap: which DocuSeal user an EA Sign company works as.
#
# An admin gives a DocuSeal user one or more Core company codes (Settings → Users →
# "EA Sign company codes"). EA Sign's editor auto-login (EaSsoController) then signs
# everyone from that company in as that user, so the editor shows — and DocuSeal
# records sends under — the company's own user instead of one shared login.
#
# Stored as a JSON array in user_configs (key ea_sign_company_codes); no migration.
# A code belongs to at most one active user per account.
module EaSignCompanyCodes
  KEY = 'ea_sign_company_codes'

  module_function

  # "mask, TEST  demo" -> ["MASK", "TEST", "DEMO"]
  def normalize(raw)
    raw.to_s.split(/[\s,;]+/).map { |c| c.strip.upcase }.compact_blank.uniq
  end

  def for_user(user)
    Array(user.user_configs.find_by(key: KEY)&.value)
  end

  # Codes in `codes` already given to another active user of the same account.
  def taken_by_others(user, codes)
    return {} if codes.empty?

    UserConfig.joins(:user)
              .where(key: KEY, users: { account_id: user.account_id, archived_at: nil })
              .where.not(user_id: user.id)
              .each_with_object({}) do |config, taken|
      (Array(config.value) & codes).each { |code| taken[code] = config.user }
    end
  end

  def save!(user, codes)
    config = user.user_configs.find_or_initialize_by(key: KEY)
    if codes.empty?
      config.destroy! if config.persisted?
    else
      config.update!(value: codes)
    end
  end

  # The active user of `account` holding `code`, or nil.
  def user_for(account, code)
    code = code.to_s.strip.upcase
    return if code.empty?

    account.users.active.joins(:user_configs).where(user_configs: { key: KEY }).order(:id).find do |user|
      for_user(user).include?(code)
    end
  end
end
