require "rails/all"

module ExplicitBeforeDefaults
  class Application < Rails::Application
    config.active_storage.variant_processor = :mini_magick
    config.load_defaults 8.1
  end
end
