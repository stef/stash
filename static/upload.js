var done = false;
var start = undefined; // will be set by 'init_upload_form()'

var time_to_str_units = [[3600, 'h'], [60, 'm'], [1, 's']];
function time_to_str(t) {
    var s = '';
    for (var i = 0; i < time_to_str_units.length; i++) {
        var unit = time_to_str_units[i];
        var q = Math.floor(t / unit[0]);
        t = t - (q * unit[0]);
        if (q) {
            s += ' ' + q.toString() + unit[1];
        }
    }
    if (!String.prototype.trimLeft) {
        // 'trim()' was introduced in JavaScript 1.8.1
        s = s.replace(/^\s+/g, '');
    } else {
        s = s.trimLeft();
    }
    return s || '0s';
}

// Function called when we receive progress information (as JSON data)
// from the server.
function callback(data) {
    if (data.state === 'uploading') {
        var now = new Date().getTime();
        var elapsed = now - start; // in milliseconds
        // Cater with a 0 value, which may happen if the upload has
        // just started, or if the file is being renamed.
        if ((data.received === 0) && (elapsed > 3000)) {
            // 3 seconds have passed. We probably have received
            // something by now, so that means that we probably have
            // received everything.
            data.received = data.size;
        }
        var percent = data.received / data.size * 100;
        var progress = document.getElementById("progress_bar");
        progress.innerHTML = Math.round(percent).toString() + "%";
        var width = Math.round(percent * (391.5 / 100));
        progress.style.width = width.toString() + "px";
        var eta_block = document.getElementById("eta");
        if (percent < 100) {
            var left = (100 - percent) / percent * elapsed;
            left = Math.round(left / 1000); // in seconds
            eta_block.innerHTML = "ETA: " + time_to_str(left);
        }
    }
    else if (data.state === 'done') {
        done = true;
    }
    else if (data.state === 'error') {
        // This only happens when using the Nginx Upload
        // Progress module. We display the status code.
        // FIXME: to be tested.
        var progress = document.getElementById("progress_bar");
        progress.innerHTML = data.status;
    }
}


function refresh_progress_bar() {
    if (!done) {
        var file_id = document.getElementById("file_id").value;
        $.getJSON("/progress?X-Progress-ID=" + file_id, callback);
    }
}

function init_upload_form() {
    $("#upload_form").submit(function() {
        var container = document.getElementById("progress_bar_container");
        container.style.display = "block";
        start = new Date().getTime();
        setInterval(refresh_progress_bar, 1000);
    });
}
