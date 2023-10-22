import requests
from flask import Flask, render_template, request,  session, redirect
import functions
import os


app = Flask(__name__)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/Traffic_form')
def Traffic_form():
    return render_template('Traffic_form.html', visibility="hidden")

@app.route('/general_health_form')
def general_health_form():
    return render_template('general_health_form.html')

@app.route('/Traffic_response', methods=("POST", "GET"))#methods=['POST']
def Traffic_response():
    data = request.form
    # print(data['src_ip'])
    # print(data['dst_ip'])
    pl = functions.LogClass()
    try:
        df = pl.log_input(data=data)
    except TypeError:
        return render_template('Traffic_form.html', visibility="show")
    else:
        if 'wrong input' in df:
            return render_template('Traffic_form.html', visibility="show")
        else:
            return render_template('Traffic_response.html', tables=[df.to_html(classes='center table')], titles=df.columns.values, visibility="hidden")#,value=pl.pull_logs(primary_device, device)


@app.route('/general_health_response', methods=("POST", "GET"))#methods=['POST']
def general_health_response():
    data = request.form
    # print(data['src_ip'])
    # print(data['dst_ip'])
    pl = functions.LogClass()
    try:
        mu = pl.get_mgmt_uptime_info(data=data)
        du = pl.get_data_uptime_info(data=data)
        ha = pl.get_ha_info(data=data)
        ps = pl.get_panorama_status(data=data)
        df = pl.get_interface(data=data)
    except requests.exceptions.ConnectionError:

        return render_template('general_health_form.html')
    else:
        return render_template('general_health_response.html', tables=[df.to_html(classes='table')], titles=df.columns.values, value=[mu, du, data['device'], ha[0], ha[1], ps])

if __name__ == "__main__":
    app.run(port=50000, debug=True)