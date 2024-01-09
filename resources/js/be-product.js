Dropzone.autoDiscover = false;
$(function() {
  fetch_image()
  let upload_image= new Dropzone(".dropzone",{
    url: BASE_URL + 'backoffice/product/upload_image',
    method:"post",
    acceptedFiles:"image/*",
    paramName:"image",
    dictInvalidFileType:"This type is not allowed!",
  })

  var product_ref = $('#product_ref').val();

  upload_image.on("sending",function(a,b,c){
    a.token=Math.random();
    c.append("token",a.token);
    c.append("product_ref",product_ref);
    c.append(INITSTATE[0], INITSTATE[1])
  });

  upload_image.on("success", function(a,b,c) {
    fetch_image()
  })
})

function fetch_image() {
  let imageLists = ''

  $.ajax({
    url: BASE_URL + 'backoffice/product/get_images?product_ref=' + $('#product_ref').val(),
    success: function(data) {
      console.log(data)

      data.data.map(img => {
        imageLists += `<div class="col-md-2 mb-3">
          <img src="${RESOURCE_URL}upload/img/${img.image}" class="img-fluid img-300" alt="">
          ${img.is_thumbnail == 1 ? '' : `<button class="btn btn-info btn-block" id="set-thumbnail" style="border-radius:0px!important" onclick="set_thumbnail('`+img.product_ref+`','`+img.token+`')">Jadikan Thumbnail</button>`}
          <button class="btn btn-danger btn-block" style="border-radius:0px!important" onclick="delete_image('`+img.product_ref+`','`+img.token+`')">Hapus</button>
        </div>`
      })

      $('#image-lists').html('');

      $('#image-lists').html(`<div class="row">${imageLists}</div>`)
    }
  })
}

function set_thumbnail(ref, token) {
  let formData = new FormData();
  formData.append("product_ref", ref)
  formData.append("token", token)
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'backoffice/product/set_thumbnail',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      console.log(data)
      fetch_image()
    },
    error: function(data){    
      console.log(data)
    }
  })
}

function delete_image(ref, token) {
  let formData = new FormData();
  formData.append("product_ref", ref)
  formData.append("token", token)
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'backoffice/product/delete_image',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      console.log(data)
      fetch_image()
    },
    error: function(data){    
      console.log(data)
    }
  })
}

if($("#product-form").length > 0 ) {
  $("#save-btn").removeAttr("disabled");
  $("#product-form").validate({
    rules: {
      title: {
        required: true,
        minlength: 2
      },
      description: {
        required: true,
        minlength: 2
      },
      category_id: {
        required: true,
      },
      status: {
        required: true,
      },
      stock: {
        required: true,
        number: true
      },
      price: {
        required: true,
        number: true
      },
      commision_maintenance: {
        required: true,
        number: true
      },
      commision_affiliator: {
        required: true,
        number: true
      },
      commision_provider: {
        required: true,
        number: true
      },
      commision_mediator: {
        required: true,
        number: true
      },
      commision_leader: {
        required: true,
        number: true
      },
      commision_cs: {
        required: true,
        number: true
      },
      weight: {
        required: true,
        number: true
      },
      long: {
        required: false,
      },
      width: {
        required: false,
      },
    },
    errorPlacement: function (error, element) {
      var name = element.attr('name');
      var type = element[0].tagName;
      var errorSelector = '.form-control-feedback[for="' + name + '"]';
      var $element = $(errorSelector);
      if ($element.length) {
          $(errorSelector).html(error.html());
      } else {
          if (type == 'SELECT') {
              error.insertAfter(element.next());
          }
          else {
              error.insertAfter(element);
          }
      }
    },
    submitHandler: function(form) {
      form.submit();
    },
   });
}