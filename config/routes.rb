Rails.application.routes.draw do
  get 'login',to:'sessions#new'
  post '/login',to:'sessions#create'
  delete '/logout',to:'sessions#destroy'


  resources :users
  post '/signup',to:'users#create'
  get '/signup',to:'users#new'




  get '/contact',to:'static_pages#contact'

  get '/home',to:'static_pages#home'

  get '/help',to: 'static_pages#help'

  get '/about',to: 'static_pages#about'
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html
  root 'static_pages#home'
end
