require 'rails_helper'

# Test suite for User model
RSpec.describe User, type: :model do
  
  # Association test
  # Ensure User model has a 1:m relationship with the Todo model
  it { should have_many(:todos) }
  
  # Validation tests
  # Ensure name, email and password_digest are present before save
  it { should validate_presence_of(:name) }
  it { should validate_presence_of(:email) }
  it { should validate_presence_of(:password_digest) }
  
end
