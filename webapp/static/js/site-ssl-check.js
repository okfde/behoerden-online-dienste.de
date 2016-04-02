$(document).ready(function(){
  //hoster
  if ($('#hoster').val() == '-1') {
    $('#hoster').parent().append('<input id="hoster-new" class="form-control" name="hoster-new">');
  }
  $('#hoster').change(function() {
    if ($('#hoster').val() == '-1') {
      $('#hoster').parent().append('<input id="hoster-new" class="form-control" name="hoster-new">');
    }
    else {
      $('#hoster-new').remove();
    }
  });
  // type
  if ($('#type').val() == '-1') {
    $('#type').parent().append('<input id="type-new" class="form-control" name="type-new">');
  }
  $('#type').change(function() {
    if ($('#type').val() == '-1') {
      $('#type').parent().append('<input id="type-new" class="form-control" name="type-new">');
    }
    else {
      $('#type-new').remove();
    }
  });
});