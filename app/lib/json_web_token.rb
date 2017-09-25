class JsonWebToken
  
  # secret to encode and decode token
  HMAC_SECRET = Rails.application.secrets.secret_key_base
  
  def self.encode(payload, exp = 24.hours.from_now)
    # Set expiry to 24 hours from creation time
    payload[:exp] = exp.to_i
    
    # Sign token with application secret
    JWT.encode(payload, HMAC_SECRET)
  end
  
  def self.decode(token)
    # Get payload --> first index
    body = JWT.decode(token, HMAC_SECRET, true, { algorithm: 'HS256'} )[0]
    HashWithIndifferentAccess.new body
    # Rescue from expiry exception
    rescue JWT::ExpiredSignature, JWT::VerificationError => e
      raise ExceptionHandler::ExpiredSignature, e.message
  end
  
end