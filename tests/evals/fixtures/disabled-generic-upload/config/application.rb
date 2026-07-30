require "rails/all"

module DisabledApp
  class Application < Rails::Application
    config.load_defaults 8.1
  end
end
