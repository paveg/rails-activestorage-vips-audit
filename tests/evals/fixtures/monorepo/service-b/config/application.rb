require "rails/all"

module ServiceB
  class Application < Rails::Application
    config.load_defaults 8.1
    config.active_storage.variant_processor = :mini_magick
  end
end
