require 'test_helper'

class UsersSingupTest < ActionDispatch::IntegrationTest
  # test "the truth" do
  #   assert true
  # end
  test "invalid signup information" do
    get signup_path
    assert_no_difference 'User.count' do
      post signup_path,params:{user:{name:"",email:"user@invalid","password":"foo",
                                    "password_confirmation":"bar"}}
    end
    assert_template 'users/new'
    assert_select 'div#error_explanation'
    assert_select 'div.field_with_errors'
  end

  test "valid signup information" do
    get signup_path
    assert_difference 'User.count',1 do
      post signup_path,params:{user:{name:"example",email:"user@example.com","password":"foobar",
                                     "password_confirmation":"foobar"}}
    end
    follow_redirect!
    assert_template 'users/show'
  end
end
