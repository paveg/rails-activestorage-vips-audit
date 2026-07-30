class DocumentsController < ApplicationController
  def document_params
    params.require(:document).permit(:scan)
  end
end
