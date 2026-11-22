User.where("name = '#{params[:name]}'")
User.where(name: params[:name])
system("convert #{params[:file]} out.png")
obj = Marshal.load(data)
<%= raw @comment.body %>
