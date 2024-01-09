const Toast = Swal.mixin({
  toast: true,
  position: 'top-end',
  showConfirmButton: false,
  timer: 3000,
  timerProgressBar: true,
  onOpen: (toast) => {
    toast.addEventListener('mouseenter', Swal.stopTimer)
    toast.addEventListener('mouseleave', Swal.resumeTimer)
  }
})

function updateTotalHargaElement(element, jumlah) {
  element.html(currency(jumlah * parseInt(productDetail.price)))
}

$('#btn-keranjang').click(function(e) {
  e.preventDefault();
  $("#body-wrapper").loading();
  
  let formData = new FormData();
  formData.append("id", productDetail.id)
  formData.append("slug", productDetail.slug)
  formData.append("image", productImages)
  formData.append("stock", productDetail.stock)
  formData.append("qty", jumlahBarang.val())
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'cart/add',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      console.log(data)
      $("#body-wrapper").loading("stop");

      Toast.fire({
        icon: data.success ? 'success' : 'error',
        title: data.message
      })

      if(data.description == 'login') {
        window.location.href = BASE_URL + 'auth/login?redirect=' + CURRENT_URL
      }
    },
    error: function(data){    
      $("#body-wrapper").loading("stop");
      console.log(data)
      Toast.fire({
        icon: data.success ? 'success' : 'error',
        title: data.message
      })

      if(data.description == 'login') {
        window.location.href = BASE_URL + 'auth/login?redirect=' + CURRENT_URL
      }
    }
  })
})

$('#btn-beli').click(function(e) {
  e.preventDefault();
  $("#body-wrapper").loading();
  
  let formData = new FormData();
  formData.append("id", productDetail.id)
  formData.append("slug", productDetail.slug)
  formData.append("image", productImages)
  formData.append("stock", productDetail.stock)
  formData.append("qty", jumlahBarang.val())
  formData.append(INITSTATE[0], INITSTATE[1])

  $.ajax({
    url: BASE_URL + 'cart/add',
    processData: false,
    contentType: false,
    data: formData,
    type: 'POST',
    success: function(data){    
      console.log(data)
      $("#body-wrapper").loading("stop");

      if(data.description == 'login') {
        window.location.href = BASE_URL + 'auth/login?redirect=' + CURRENT_URL
        return
      }

      if(data.success) {
        window.location.href = BASE_URL + 'home/checkout'
      }
    },
    error: function(data){    
      $("#body-wrapper").loading("stop");
      console.log(data)

      if(data.description == 'login') {
        window.location.href = BASE_URL + 'auth/login?redirect=' + CURRENT_URL
      }
    }
  })
})