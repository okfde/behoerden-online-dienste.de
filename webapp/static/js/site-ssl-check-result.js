$(document).ready(function(){
  $.get('/api/ssl-details-html?host=' + $('h1').attr('data-host'), function(data) {
    $('#wait').remove();
    $('#result-box').append(data);
  });
});