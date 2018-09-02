class User < ApplicationRecord
  attr_accessor :remember_token
  before_save {self.email=email.downcase}
  validates :name,presence:true,length:{maximum:50}
  validates :email,presence:true,length:{maximum:50},
            format:{with:/\A[\w+\-.]+@[a-z\d\-.]+\.[a-z]+\z/i},uniqueness:{case_sensitive:false}
  validates :password,presence:true,length:{minimum:6}
  has_secure_password

  #为固件生成密码的哈希值
  def User.digest(string)
    cost=ActiveModel::SecurePassword.min_cost ? BCrypt::Engine::MIN_COST:
             BCrypt::Engine.cost
    BCrypt::Password.create(string,cost:cost)
  end
  #生成一个随机的令牌
  def User.new_token
    SecureRandom.urlsafe_base64
  end
  #为了持久保存会话，在数据库记住用户
  def remember
    self.remember_token=User.new_token
    update_attribute(:remember_digest,User.digest(remember_token))
  end
  #匹配指定的令牌和数据库的摘要匹配
  def  authenticated?(remember_token)
    return  false if self.remember_digest.nil?
    BCrypt::Password.new(remember_digest).is_password?(remember_token)
  end
  #忘记用户
  def forget
    update_attribute(:remember_digest,nil)
  end
end
