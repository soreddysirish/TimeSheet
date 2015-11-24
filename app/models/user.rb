class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  validates_presence_of :email,:password,:role
  validates :password, confirmation: true
  validates :email,uniqueness:{message:'email is already registered'}
  validates :password, :format => {with: /^(?=.*[a-zA-Z])(?=.*[0-9]).{6,}$/,multiline:true,message:'password must be one uppercase one lowercase and one special charecter'}
  devise :database_authenticatable,
         :recoverable, :rememberable, :trackable, :validatable

         enum role:[:delivery_manager, :tech_lead,:developer]
end
