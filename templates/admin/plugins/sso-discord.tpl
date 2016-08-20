<form id="discordSettings">
    <div class="row">
        <div style="display:inline-block">
          <label style="padding: 3px;">Client ID:</label> <input type="text" data-key="appDetails.clientID" style="float:right;"></input><br />
          <label style="padding: 3px;">Secret:</label> <input type="password" data-key="appDetails.secret" style="float: right;"></input><br />
          <button style="margin-top: 20px; margin-right: -25px; float: right;" class="btn btn-lg btn-primary" id="save">Save</button>
        </div>
    </div>
</form>

<script>
    require(['settings'], function (settings) {
        var wrapper = $('#discordSettings');
        settings.sync('discordSSO', wrapper);
        $('#save').click(function(event) {
            event.preventDefault();
            settings.persist('discordSSO', wrapper, function(){
                socket.emit('admin.settings.syncDiscordSettings');
            });
        });
      });
</script>
