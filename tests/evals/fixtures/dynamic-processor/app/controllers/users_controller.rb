class UsersController < ApplicationController
  def user_params
    params.require(:user).permit(:avatar)
  end
end
