/* <script src="https://code.jquery.com/jquery-3.4.1.slim.min.js"
        integrity="sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n"
        crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js"
        integrity="sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo"
        crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js"
        integrity="sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6"
        crossorigin="anonymous"></script>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/js-sha1/0.7.0/sha1.min.js"></script>
    <script type="text/javascript" src="https://cdn.jsdelivr.net/npm/bootpag@5.0.1/dist/jquery.bootpag.min.js"></script>
    <script type="text/javascript"
        src="https://cdn.jsdelivr.net/npm/jquery-validation@1.19.5/dist/jquery.validate.min.js"></script> */

import './_jquery.js'
import 'bootpag'
import { sha1 } from 'sha1'




const serverport = 8000;
const serveraddr = `${window.location.protocol}//127.0.0.1:${serverport}/dashboard`;
function updatetable() {
  if (iseventview) {
    eventtable.removeClass('d-none')
    detectiontable.addClass('d-none')
    eventbtn.addClass('btn-success')
    detectionbtn.removeClass('btn-success')
  } else {
    detectiontable.removeClass('d-none')
    eventtable.addClass('d-none')
    eventbtn.removeClass('btn-success')
    detectionbtn.addClass('btn-success')
  }
}
function filleventtable(id) {
  $.ajax({
    url: serveraddr + '/getuserevent?id=' + id,
    method: 'GET',
    contentType: 'application/json',
    beforeSend: () => {
      $('#tablebodyevent').append('<p>loading</p>')
    },
    success: (data, status) => {
      let pass = false
      let page_list = []
      const list = JSON.parse(data.message)
      console.log(list.length)
      let html = ''
      let ind = 0
      list.forEach((curval, index) => {
        html += '<tr>'
        for (const key in curval) {
          if (pass == false) {
            pass = true
            continue

          }
          html += '<td>' + '<bold>' + key + ' </bold>' + ': ' + curval[key] + '</td>'
        }
        html += '</tr>'
        pass = false
        if (ind == 9) {
          page_list.push(html)
          ind = 0
          html = ''

        } else {
          ind++
        }
      })

      page_list.push(html)
      $('#page-selection-event').bootpag({
        total: page_list.length,
        page: 1,
        maxVisible: 10
      }).on('page', function (event, num) {
        $('#tablebodyevent').empty()
        $('#tablebodyevent').append(page_list[num - 1])
        $(this).bootpag({ page: num })
      })
      $('#page-selection-event').trigger('page', [1])

    },
    error: (data, status) => {
      console.log(data)
      $('#testp').text('error while loading log')
    }
  }
  )
  $.ajax({
    url: serveraddr + '/getdetectionalert?id=' + id,
    method: 'GET',
    contentType: 'application/json',
    beforeSend: () => {
      $('#tablebodydetection').append('<p>loading</p>')
    },
    success: (data, status) => {
      console.log(data)
      let pass = false
      let page_list_detect = []
      const list = JSON.parse(data.message)
      let html = ''
      let ind = 0
      list.forEach((curval, index) => {
        html += '<tr>'
        for (const key in curval) {
          if (pass == false) {
            pass = true
            continue

          }
          if (key == 'eventrowid') {
            html += `<td><bold>event</bold>: <button class ="btn btn-warning eventrowbtn" eventid="${curval[key]}">Show</button></td>`
            //  html += '<td>' + '<bold>' + key + ' </bold>' + ': <button class ="btn btn-warning eventrowbtn" eventid="${curval[key]}">' + curval[key] + '</button></td>'
          } else {
            html += '<td>' + '<bold>' + key + ' </bold>' + ': ' + curval[key] + '</td>'
          }

        }
        html += '</tr>'
        pass = false
        if (ind == 9) {
          page_list_detect.push(html)
          ind = 0
          html = ''

        } else {
          ind++
        }
      })
      page_list_detect.push(html)
      $('#page-selection-detection').bootpag({
        total: page_list_detect.length,
        page: 1,
        maxVisible: 10
      }).on('page', function (event, num) {
        $('#tablebodydetection').empty()
        $('#tablebodydetection').append(page_list_detect[num - 1])
        $(this).bootpag({ page: num })
      })
      $('#page-selection-detection').trigger('page', [1])

      $('.eventrowbtn').on('click', (event) => {
        let num = $(event.target).attr('eventid')
        num = parseInt(num)
        $.ajax({
          url: serveraddr + '/getsingleevent?id=' + num,
          method: 'GET',
          contentType: 'application/json',
          beforeSend: () => {
            $('#showtable').empty()
            $('#showtable').append('loading')
          },
          success: (data, status) => {
            console.log(data)
            let pass = false
            const evt = JSON.parse(data.message)
            console.log(list.length)
            let html = ''
            html += '<tr>'
            for (const key in evt) {
              if (pass == false) {
                pass = true
                continue

              }
              html += '<td>' + '<bold>' + key + ' </bold>' + ': ' + evt[key] + '</td>'
            }
            html += '</tr>'
            pass = false
            $('#showtable').empty()
            $('#showtable').append(html)
          },
          error: (data, status) => {
            $('#testp').text(data.responseJSON['message'])
          }
        }
        )
      })
    },
    error: (data, status) => {
      $('#testp').text(data.responseJSON['message'])
    }
  }
  )
}
let iseventview = false
const eventtable = $('#eventtable')
const detectiontable = $('#detectiontable')
const eventbtn = $('#eventbtn')
const detectionbtn = $('#detectionbtn')
updatetable()
$.ajax({
  url: serveraddr + '/getuserlist',
  method: 'GET',
  contentType: 'application/json',
  success: (data, status) => {
    const list = JSON.parse(data.message)
    if (list.length == 0) {
      return
    }
    const first_user = list[0]['username']
    list.forEach((curval, index) => {
      let id = index + 1
      $('#dropdownmenu').append('<a class="dropdown-item" userid=' + id + '>' + curval['username'] + '</a>')
    })
    $('#dropdownMenuButton').text(first_user)
    filleventtable(1)
    $('.dropdown-item').on('click', (event) => {
      const user = $(event.target).text()
      const idtext = $(event.target).attr('userid')
      const id = parseInt(idtext)
      $('#dropdownMenuButton').text(user)
      filleventtable(id)
    })
    //   dropdownMenuButton
  },
  error: (data, status) => {
    $('#testp').text(data.responseJSON['message'])
  }
}
)


const form = $('#user_form')
form.on('submit', function (event) {
  event.preventDefault()
  const usernametx = $('#username').val()
  let passwordtx = $('#password').val()
  const payload = {
    username: usernametx,
    password: passwordtx
  }
  $.ajax({
    url: serveraddr + '/createuser',
    method: 'POST',
    data: JSON.stringify(payload),
    contentType: 'application/json',
    success: (data, status) => {
      console.log(data)
      $('#submit_msg').text(data.message)
    },
    error: (data, status) => {
      $('#submit_msg').text(data.responseJSON['message'])
    }
  }
  )
})
$('#eventbtn').on('click', () => {
  if (iseventview == true) {
    return
  }
  iseventview = true
  updatetable()
})
$('#detectionbtn').on('click', () => {
  if (iseventview == false) {
    return
  }
  iseventview = false
  updatetable()
})
$('#gotopagebtn').on('click', () => {
  let page_selection = $('#page-selection-event')
  if (!iseventview) {
    page_selection = $('#page-selection-detection')
  }
  let input = $('#gotopageinput').val()
  input = parseInt(input)
  if (input < 1) {
    input = 1
  }
  if (!Number.isInteger(input)) {
    alert('input valid value')
    return
  }
  page_selection.trigger('page', [input])
})
