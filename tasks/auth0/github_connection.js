function (user, context, callback) {
    // access token to talk to github API
    var github = user.identities.filter(function (id){
        return id.provider === 'github';
    })[0];
    var access_token = github.access_token;
    request.get({
        url: "https://api.github.com/user/teams",
        headers: {
            // use token authorization to talk to github API
            "Authorization": "token "+access_token,
            "User-Agent": "${USER_AGENT}",
        }
    }, function(err, res, data){
        user.err = err;
        if(data){
            // extract github team names to array
            var parsed = JSON.parse(data)
            var github_teams = parsed.map(function(team){
                return team.organization.login + "/" + team.slug;
            });
            // add teams to the application metadata
            user.app_metadata = user.app_metadata || {};
            // update the app_metadata that will be part of the response
            user.app_metadata.roles = github_teams;

            // persist the app_metadata update
            auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
                .then(function(){
                    callback(null, user, context);
                })
                .catch(function(err){
                    callback(err);
                });
        }
    });
}