let ElasticEmail = require('@elasticemail/elasticemail-client');
 
let defaultClient = ElasticEmail.ApiClient.instance;
 
let apikey = defaultClient.authentications['apikey'];
apikey.apiKey = process.env.NEXT_PUBLIC_ELASTIC_EMAIL_API_KEY
 
let api = new ElasticEmail.EmailsApi()
 
let email = ElasticEmail.EmailMessageData.constructFromObject({
  Recipients: [
    new ElasticEmail.EmailRecipient("korneophusedm938@gmail.com")
  ],
  Content: {
    Body: [
      ElasticEmail.BodyPart.constructFromObject({
        ContentType: "HTML",
        Content: "My test email content ;)"
      })
    ],
    Subject: "JS EE lib test",
    From: "rohelakormoker8@gmail.com"
  }
});
 
var callback = function(error, data, response) {
  if (error) {
    console.error(error);
  } else {
    console.log('API called successfully.');
  }
};
api.emailsPost(email, callback);