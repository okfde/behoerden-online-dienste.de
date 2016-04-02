$(document).ready(function() {
  $('#region-host-button a').click(function(event) {
    event.preventDefault();
    $('#region-host-form').css({'display': 'block'});
  });
  $('#new-host-type').change(function() {
    if ($('#new-host-type').val() == '-1') {
      $('#new-host-type').replaceWith('<input name="new-host-type" id="new-host-type" class="form-control" placeholder="Dienst zur KFZ-Anmeldung">');
    }
  });
  
  // index
	if ($('#fsrb').exists()) {
		$.fastsearchlocations_live = {
			'settings': {
				url: '/api/region-search-live',
				param: 'q',
				delay: 100,
				loading_css: '#loading'
			},
			show_results: function(result) {
				result = result['response'];
				result_html = '<ul>';
				if (result.length) {
					$('#fsrtl').css({'display': 'block'});
					for (i = 0; i < result.length; i++) {
						result_html += '<li data-slug="' + result[i]['slug'] + '\">';
            if (result[i]['postalcode'])
              result_html += result[i]['postalcode'] + ' ';
            result_html += result[i]['name'] + '</li>';
					}
					result_html += '</ul>';
					$('#fsrtl').html(result_html);
					$('#fsrtl li').click(function() {
						window.location.href = '/region/' + $(this).attr('data-slug');
					});
				}
				else
					$('#fsrtl').css({'display': 'none'});
			},
			loading: function() {
				$($.fastsearchlocations_live.settings.loading_css).show()
			},
			resetTimer: function(timer) {
				if (timer) clearTimeout(timer)
			},
			idle: function() {
				$($.fastsearchlocations_live.settings.loading_css).hide()
			},
			process: function(terms) {
				var path = $.fastsearchlocations_live.settings.url.split('?'),
					query = [$.fastsearchlocations_live.settings.param, '=', terms].join(''),
					base = path[0], params = path[1], query_string = query
				
				if (params) query_string = [params.replace('&amp;', '&'), query].join('&')
				
				$.get([base, '?', query_string].join(''), function(data) {
					$.fastsearchlocations_live.show_results(data);
				})
			},
			start: function() {
				$(document).trigger('before.searchbox')
				$.fastsearchlocations_live.loading()
			},
			
			stop: function() {
				$.fastsearchlocations_live.idle()
				$(document).trigger('after.searchbox')
			}
		}
		$.fn.fastsearchlocations_live = function(config) {
			var settings = $.extend(true, $.fastsearchlocations_live.settings, config || {})
			
			$(document).trigger('init.searchbox')
			$.fastsearchlocations_live.idle()
			
			return this.each(function() {
				var $input = $(this)
				
				$input
				.ajaxStart(function() { $.fastsearchlocations_live.start() })
				.ajaxStop(function() { $.fastsearchlocations_live.stop() })
				.keyup(function(evt) {
					if ($input.val() != this.previousValue && evt.keyCode != 13) {
						$.fastsearchlocations_live.resetTimer(this.timer)
						
						this.timer = setTimeout(function() {  
							$.fastsearchlocations_live.process($input.val())
						}, $.fastsearchlocations_live.settings.delay)
						
						this.previousValue = $input.val()
					}
				})
			})
		}
		$('#fsrt').fastsearchlocations_live({});
		
		$('#fsrt').keydown(function(evt){
			// Enter abfangen
			if (evt.keyCode == 13) {
				evt.preventDefault();
				if ($('#fsrtl li.highlighted').length && $('#fsrt').val()) {
					$('#fsrtl li.highlighted').trigger('click');
				}
			}
			if (evt.keyCode == 27) {
				$('#fsrtl').css({'display': 'none'});
			}
			// Pfeil hoch abfangen
			if (evt.keyCode == 38) {
				evt.preventDefault();
				if ($('#fsrtl li.highlighted').length) {
					before = $('#fsrtl li.highlighted').prev();
					if (before.length) {
						$('#fsrtl li.highlighted').removeClass('highlighted');
						before.addClass('highlighted');
					}
				}
			}
			// Pfeil runter abfangen
			if (evt.keyCode == 40) {
				evt.preventDefault();
				if ($('#fsrtl li.highlighted').length) {
					next = $('#fsrtl li.highlighted').next();
					if (next.length) {
						$('#fsrtl li.highlighted').removeClass('highlighted');
						next.addClass('highlighted');
					}
				}
				else
					$('#fsrtl li').first().addClass('highlighted');
			}
		});
		
		$('#fsrs').click(function(evt){
			evt.preventDefault();
			$('#fsrtl').css({'display': 'none'});
		});
		
		$('#fsrf').submit(function(evt){
			evt.preventDefault();
			$('#fsrtl').css({'display': 'none'});
		});
	} 
});


jQuery.fn.exists = function(){
	return this.length>0;
}