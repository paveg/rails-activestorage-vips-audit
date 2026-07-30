require "rails/all"

module ExposedApp
  class Application < Rails::Application
    config.load_defaults 8.1
  end
end
