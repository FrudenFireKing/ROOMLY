import os
from flask import Flask, request, render_template, jsonify
from diffusers import StableDiffusionPipeline
# В начале файла app.py (среди других импортов)
from deep_translator import GoogleTranslator
translator = GoogleTranslator(source='ru', target='en')  # Инициализация переводчика
import torch
import uuid
from PIL import Image
import io
import base64
from gigachat import GigaChat
from gigachat.models import Chat, Messages, MessagesRole


app = Flask(__name__)


model_id = "stabilityai/stable-diffusion-2-1-base"
device = "cuda" if torch.cuda.is_available() else "cpu"

# Загрузка модели генерации изображений
pipe = StableDiffusionPipeline.from_pretrained(
    model_id,
    torch_dtype=torch.float16 if device == "cuda" else torch.float32,
    use_auth_token=False
)
pipe = pipe.to(device)

# Оптимизация для GPU
if device == "cuda":
    try:
        pipe.enable_xformers_memory_efficient_attention()
        if hasattr(torch, 'compile'):
            pipe.unet = torch.compile(pipe.unet, mode="reduce-overhead", fullgraph=True)
    except:
        pass


gigachat = GigaChat(
    credentials='MWE0ZmRjZjAtNzc3ZS00Y2IwLWExYjQtMWI4MTVkYzk5YTQ4OmI0MDgyNTE2LTEyMzktNDAyYi1iZGI1LTM3NmIyZDFhN2MyZg==',
    verify_ssl_certs=False
)


def extract_requirements(text):
    try:

        messages = [
            {
                "role": "user",
                "content": f"""Проанализируй текст и выдели ТОЛЬКО конкретные требования к переговорной комнате. 
                Отвечай строго в формате списка без пояснений. Пример:
                - стол на 6 человек
                - проектор
                - бронирование на среду с 14:00 до 16:00
                - люди делаю то то и то то

                Текст: "{text}"
                """
            }
        ]

        chat = Chat(
            messages=messages,
            temperature=0.7,
            max_tokens=1000
        )

        response = gigachat.chat(chat)
        requirements = [line.strip() for line in response.choices[0].message.content.split('\n') if line.strip()]
        return requirements
    
    except Exception as e:
        print(f"Ошибка GigaChat: {str(e)}")
        return []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_image():
    description = request.form.get('description')
    if not description:
        return jsonify({'error': 'Описание не предоставлено'}), 400

    try:
        translated_description = translator.translate(description)
    except Exception as e:
        return jsonify({'error': f'Ошибка перевода: {str(e)}'}), 500

    prompt = f"Modern meeting room, {translated_description}, professional design, high quality, realistic"

    try:
        image = pipe(
            prompt,
            num_inference_steps=15,
            guidance_scale=7.5,
            width=512,
            height=512
        ).images[0]

        buffered = io.BytesIO()
        image.save(buffered, format="PNG")
        img_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')

        return jsonify({
            'image': f'data:image/png;base64,{img_base64}',
            'status': 'Генерация завершена!'
        })

    except Exception as e:
        return jsonify({'error': f'Ошибка генерации: {str(e)}'}), 500

@app.route('/analyze', methods=['POST'])
def analyze_text():
    user_input = request.form.get('user_input')
    if not user_input:
        return jsonify({'error': 'Текст не предоставлен'}), 400
    
    requirements = extract_requirements(user_input)
    return jsonify({'requirements': requirements})

if __name__ == '__main__':
    app.run(debug=True)